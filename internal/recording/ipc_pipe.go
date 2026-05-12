package recording

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	gblob "gocloud.dev/blob"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/encoding/protodelim"
	"google.golang.org/protobuf/proto"

	"github.com/pomerium/envoy-custom/api/x/recording"
	"github.com/pomerium/envoy-custom/api/x/recording/formats/ssh"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/protoutil"
	"github.com/pomerium/pomerium/pkg/storage/blob/middleware"
)

var magicBytes = []byte{0xFF, 0xFF, 0xFF, 0xFF}

type Pipes struct {
	uploadRead  *os.File
	uploadRd    protodelim.Reader
	uploadWrite *os.File

	checkpointRead  *os.File
	checkpointWrite *os.File

	cfgMu  sync.Mutex
	bucket *gblob.Bucket
	prefix string

	shouldShutdown atomic.Bool
}

// SetupRecordingPipes creates the number of required pipes according to
// the concurrency set in the ssh session recording config,
// and mutates that configuration in place with the actual pipes config
func SetupRecordingPipes(cfg *ssh.Config) ([]*Pipes, error) {
	recPipes := []*Pipes{}
	n := cfg.GetUploadConfig().GetConcurrency()
	for range n.Value {
		uploadRead, uploadWrite, err := os.Pipe()
		if err != nil {
			for _, comm := range recPipes {
				_ = comm.Close()
			}
			return nil, err
		}
		checkpointRead, checkpointWrite, err := os.Pipe()
		if err != nil {
			_ = uploadRead.Close()
			_ = uploadWrite.Close()
			for _, comm := range recPipes {
				_ = comm.Close()
			}
			return nil, err
		}
		recPipes = append(recPipes, &Pipes{
			uploadRead:      uploadRead,
			uploadWrite:     uploadWrite,
			uploadRd:        bufio.NewReaderSize(uploadRead, maxChunkSize*2),
			checkpointRead:  checkpointRead,
			checkpointWrite: checkpointWrite,
		})
	}
	return recPipes, nil
}

var _ TransportProtocol = (*Pipes)(nil)

type PipeIPC struct {
	pipes         []*Pipes
	identity      string
	bucket        *gblob.Bucket
	managedPrefix string

	doneC chan struct{}
}

func (p *PipeIPC) OnChange(bucket *gblob.Bucket, managedPrefix string) {
	for _, pipe := range p.pipes {
		pipe.OnChange(bucket, managedPrefix)
	}
}

func NewPipeIPC(identity string, bucket *gblob.Bucket, managedPrefix string, pipes []*Pipes) *PipeIPC {
	return &PipeIPC{
		pipes:         pipes,
		identity:      identity,
		bucket:        bucket,
		managedPrefix: managedPrefix,
		doneC:         make(chan struct{}, 1),
	}
}

func (p *PipeIPC) Shutdown(ctx context.Context) error {
	errs := []error{}
	for _, pipe := range p.pipes {
		pipe.shouldShutdown.Store(true)
		err := pipe.uploadRead.SetReadDeadline(time.Unix(1, 0)) // unblocks read immediately
		if err != nil {
			errs = append(errs, err)
		}
	}
	timeoutDur := time.Minute * 2
	select {
	case <-p.doneC:
		log.Ctx(ctx).Info().Msg("session recording pipe transport gracefully shutdown")
	case <-time.After(timeoutDur):
		log.Ctx(ctx).Warn().Dur("timeout", timeoutDur).
			Msg("failed to gracefully shutdown session recording pipe transport")
		return fmt.Errorf("recording pipe transport graceful shutdown timed out :%w", errors.Join(errs...))
	}
	return nil
}

func (p *Pipes) Close() error {
	urErr := p.uploadRead.Close()
	uwErr := p.uploadWrite.Close()
	crErr := p.checkpointRead.Close()
	cwErr := p.checkpointWrite.Close()
	return errors.Join(urErr, uwErr, crErr, cwErr)
}

func (p *Pipes) shutdownRequested() bool {
	return p.shouldShutdown.Load()
}

func (p *Pipes) recvRecordingMsg() (*recording.RecordingData, error) {
	if p.shutdownRequested() {
		n, err := unix.IoctlGetInt(int(p.uploadRead.Fd()), FIONREAD)
		if err != nil {
			return nil, err
		}
		if n == 0 {
			// nothing queued up, safe to signal close
			if err := p.Close(); err != nil {
				return nil, err
			}
			return nil, io.EOF
		}
		// otherwise, continues to drain
	}
	data, err := readProtoHelper[*recording.RecordingData](p.uploadRd)
	return data, err
}

func (p *Pipes) sendServerManifest(msg *recording.RecordingCheckpoint) error {
	return sendProtoHelper(p.checkpointWrite, []*recording.RecordingCheckpoint{msg})
}

func (p *Pipes) Recv(_ context.Context) (*recording.RecordingData, error) {
	return p.recvRecordingMsg()
}

func (p *Pipes) Send(_ context.Context, s *recording.RecordingCheckpoint) error {
	return p.sendServerManifest(s)
}

func (p *Pipes) OnChange(bucket *gblob.Bucket, managedPrefix string) {
	p.cfgMu.Lock()
	defer p.cfgMu.Unlock()
	p.bucket, p.prefix = bucket, managedPrefix
}

func (p *Pipes) currentConfig() (bucket *gblob.Bucket, managedPrefix string) {
	p.cfgMu.Lock()
	defer p.cfgMu.Unlock()
	return p.bucket, p.prefix
}

func (p *Pipes) EnvoyFds() []*os.File {
	return []*os.File{p.checkpointRead, p.uploadWrite}
}

func newProtoMessage[T proto.Message]() T {
	var zero T
	t := reflect.TypeOf(zero)
	if t.Kind() == reflect.Pointer {
		return reflect.New(t.Elem()).Interface().(T)
	}
	return zero
}

// Serve is a long-lived, called-once method to start reading and writing
// session recording protocol messages to pipes
func (p *PipeIPC) Serve(ctx context.Context) error {
	ctx = middleware.ContextWithBlobUserAgent(ctx, p.identity)
	eg, ctxca := errgroup.WithContext(ctx)
	defer close(p.doneC)
	for _, pipeCfg := range p.pipes {
		eg.Go(func() error {
			hello := [4]byte{}
			if _, err := pipeCfg.uploadRead.Read(hello[:]); err != nil {
				return err
			} else if !bytes.Equal(hello[:], magicBytes) {
				return fmt.Errorf("received incorrect hello message")
			}
			log.Ctx(ctx).Info().Any("fd", pipeCfg.uploadRead).Msg("received hello on upload pipe")
			p := &Protocol{
				runCtx:            ctxca,
				tr:                pipeCfg,
				maxChunkSize:      maxChunkSize,
				initBucket:        p.bucket,
				initManagedPrefix: p.managedPrefix,
			}
			return p.Run()
		})
	}
	err := eg.Wait()
	return err
}

func readProtoHelper[T proto.Message](rd protodelim.Reader) (T, error) {
	t := newProtoMessage[T]()
	if err := protodelim.UnmarshalFrom(rd, t); err != nil {
		return t, err
	}
	return t, nil
}

func sendProtoHelper[T proto.Message](wr io.Writer, msgs []T) error {
	data, err := protoutil.MarshalLengthDelimited(msgs)
	if err != nil {
		return err
	}
	if _, err := wr.Write(data); err != nil {
		return err
	}
	return nil
}
