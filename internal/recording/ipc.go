package recording

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"

	gblob "gocloud.dev/blob"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	"github.com/pomerium/envoy-custom/api/x/recording"
	"github.com/pomerium/envoy-custom/api/x/recording/formats/ssh"
)

type pipeIPC struct {
	uploadRead  *os.File
	uploadWrite *os.File

	checkpointRead  *os.File
	checkpointWrite *os.File

	bucket        *gblob.Bucket
	managedPrefix string
}

var _ TransportProtocol = (*pipeIPC)(nil)

func NewPipeIPC(bucket *gblob.Bucket, managedPrefix string) (*pipeIPC, error) {
	// TODO : we should be able to specify specific file descriptors
	uploadRead, uploadWrite, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	checkpointRead, checkpointWrite, err := os.Pipe()
	if err != nil {
		_ = uploadRead.Close()
		_ = uploadWrite.Close()
		return nil, err
	}
	return &pipeIPC{
		uploadRead:      uploadRead,
		uploadWrite:     uploadWrite,
		checkpointRead:  checkpointRead,
		checkpointWrite: checkpointWrite,
		bucket:          bucket,
		managedPrefix:   managedPrefix,
	}, nil
}

func (p *pipeIPC) SetPipesFD() *ssh.UploadConfig {
	// TODO : this will live somewhere else... just a placeholder for now
	return &ssh.UploadConfig{
		ConnectionMode: &ssh.UploadConfig_Pipe_{
			Pipe: &ssh.UploadConfig_Pipe{
				WriteFd: int32(p.uploadWrite.Fd()),
				ReadFd:  int32(p.checkpointRead.Fd()),
			},
		},
	}
}

func (p *pipeIPC) Close() error {
	urErr := p.uploadRead.Close()
	uwErr := p.uploadWrite.Close()
	crErr := p.checkpointRead.Close()
	cwErr := p.checkpointWrite.Close()
	return errors.Join(urErr, uwErr, crErr, cwErr)
}

func readProtoHelper[T proto.Message](rd io.Reader) (T, error) {
	t := newProtoMessage[T]()
	r := bufio.NewReader(rd)
	length, err := binary.ReadUvarint(r)
	if err != nil {
		return t, fmt.Errorf("failed to read proto size from pipe : %w", err)
	}
	msg := make([]byte, length)
	if _, err := io.ReadFull(r, msg); err != nil {
		return t, fmt.Errorf("failed to read full proto message from pipe: %w", err)
	}
	if err := proto.Unmarshal(msg, t); err != nil {
		return t, fmt.Errorf("failed to unmarshal message received from pipe : %w", err)
	}
	return t, nil
}

func (p *pipeIPC) recvRecordingMsg() (*recording.RecordingData, error) {
	return readProtoHelper[*recording.RecordingData](p.uploadRead)
}

func sendProtoHelper[T proto.Message](wr io.Writer, msg T) error {
	data, err := proto.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to marshal proto message : %w", err)
	}
	w := bufio.NewWriter(wr)
	var buf []byte
	buf = protowire.AppendVarint(buf, uint64(len(data)))
	buf = append(buf, data...)
	if _, err := w.Write(buf); err != nil {
		return fmt.Errorf("failed to write to pipe : %w", err)
	}
	return nil
}

func (p *pipeIPC) sendServerManifest(msg *recording.RecordingSession) error {
	return sendProtoHelper(p.checkpointWrite, msg)
}

func newProtoMessage[T proto.Message]() T {
	var zero T
	t := reflect.TypeOf(zero)
	if t.Kind() == reflect.Pointer {
		return reflect.New(t.Elem()).Interface().(T)
	}
	return zero
}

func (p *pipeIPC) Recv(_ context.Context) (*recording.RecordingData, error) {
	return p.recvRecordingMsg()
}

func (p *pipeIPC) Send(_ context.Context, s *recording.RecordingSession) error {
	return p.sendServerManifest(s)
}

func (p *pipeIPC) Serve(ctx context.Context) error {
	return RunProtocol(ctx, p, p.bucket, p.managedPrefix)
}
