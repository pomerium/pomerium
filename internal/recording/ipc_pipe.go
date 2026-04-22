package recording

import (
	"bufio"
	"context"
	"errors"
	"io"
	"os"
	"reflect"

	gblob "gocloud.dev/blob"
	"golang.org/x/sync/errgroup"
	"google.golang.org/protobuf/encoding/protodelim"
	"google.golang.org/protobuf/proto"

	"github.com/pomerium/envoy-custom/api/x/recording"
	"github.com/pomerium/envoy-custom/api/x/recording/formats/ssh"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

type RecordingPipes struct {
	uploadRead  *os.File
	uploadRd    protodelim.Reader
	uploadWrite *os.File

	checkpointRead  *os.File
	checkpointWrite *os.File
}

// SetupRecordingPipes creates the number of required pipes according to
// the concurrency set in the ssh session recording config,
// and mutates that configuration in place with the actual pipes config
func SetupRecordingPipes(cfg *ssh.Config) ([]*RecordingPipes, error) {
	recPipes := []*RecordingPipes{}
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
		recPipes = append(recPipes, &RecordingPipes{
			uploadRead:      uploadRead,
			uploadWrite:     uploadWrite,
			uploadRd:        bufio.NewReader(uploadRead),
			checkpointRead:  checkpointRead,
			checkpointWrite: checkpointWrite,
		})
	}

	envoyPipesDesc := []*ssh.UploadConfig_PipeIpc_FdPair{}

	for _, comm := range recPipes {
		envoyPipesDesc = append(envoyPipesDesc, &ssh.UploadConfig_PipeIpc_FdPair{
			ReadFd:  int32(comm.checkpointRead.Fd()),
			WriteFd: int32(comm.uploadWrite.Fd()),
		})
	}
	cfg.UploadConfig.IpcMode = &ssh.UploadConfig_PipeIpc_{
		PipeIpc: &ssh.UploadConfig_PipeIpc{
			Pipes: envoyPipesDesc,
		},
	}
	return recPipes, nil
}

var _ TransportProtocol = (*RecordingPipes)(nil)

type pipeIPC struct {
	pipes []*RecordingPipes

	// TODO : this should pull current configuration
	bucket        *gblob.Bucket
	managedPrefix string
}

// TODO : pipeIPC needs to get bucket configuration updates
func NewPipeIPC(bucket *gblob.Bucket, managedPrefix string, pipes []*RecordingPipes) *pipeIPC {
	return &pipeIPC{
		pipes:         pipes,
		bucket:        bucket,
		managedPrefix: managedPrefix,
	}
}

func (p *pipeIPC) Close() error {
	errs := []error{}
	for _, pipe := range p.pipes {
		if err := pipe.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (p *RecordingPipes) Close() error {
	urErr := p.uploadRead.Close()
	uwErr := p.uploadWrite.Close()
	crErr := p.checkpointRead.Close()
	cwErr := p.checkpointWrite.Close()
	return errors.Join(urErr, uwErr, crErr, cwErr)
}

func (p *RecordingPipes) recvRecordingMsg() (*recording.RecordingData, error) {
	return readProtoHelper[*recording.RecordingData](p.uploadRd)
}

func (p *RecordingPipes) sendServerManifest(msg *recording.RecordingCheckpoint) error {
	return sendProtoHelper(p.checkpointWrite, []*recording.RecordingCheckpoint{msg})
}

func (p *RecordingPipes) Recv(_ context.Context) (*recording.RecordingData, error) {
	return p.recvRecordingMsg()
}

func (p *RecordingPipes) Send(_ context.Context, s *recording.RecordingCheckpoint) error {
	return p.sendServerManifest(s)
}
func newProtoMessage[T proto.Message]() T {
	var zero T
	t := reflect.TypeOf(zero)
	if t.Kind() == reflect.Pointer {
		return reflect.New(t.Elem()).Interface().(T)
	}
	return zero
}

// maybe here we need to handle bucket close errors and restart the errorgroup.
func (p *pipeIPC) Serve(ctx context.Context) error {
	eg, ctxca := errgroup.WithContext(ctx)
	for _, pipeCfg := range p.pipes {
		eg.Go(func() error {
			return RunProtocol(ctxca, pipeCfg, p.bucket, p.managedPrefix)
		})
	}
	return eg.Wait()
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
