package recording

import (
	"bufio"
	"context"
	"crypto/md5"
	"fmt"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/encoding/protodelim"
	"google.golang.org/protobuf/testing/protocmp"

	"github.com/pomerium/envoy-custom/api/x/recording"
	xrecording "github.com/pomerium/envoy-custom/api/x/recording"
	"github.com/pomerium/envoy-custom/api/x/recording/formats/ssh"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/pkg/protoutil"
	"github.com/pomerium/pomerium/pkg/storage/blob"
)

// defaults

func defaultTestConfig(bucketURI string) *config.Config {
	return &config.Config{
		Options: &config.Options{
			BlobStorage: &blob.StorageConfig{
				BucketURI:     bucketURI,
				ManagedPrefix: "test",
			},
		},
	}
}

func defaultGRPCRecordingServer(t *testing.T, cfg *config.Config) Server {
	t.Helper()
	srv, err := NewRecordingServer(t.Context(), cfg, TransportOptions{
		TransportMode: "grpc",
		Concurrency:   uint32(666),
	})
	require.NoError(t, err)
	return srv
}

// testcases

type protocolTestcase struct {
	name string
	in   []*xrecording.RecordingData
	out  []testcaseRecv
}

type testcaseRecv struct {
	msg     *xrecording.RecordingCheckpoint
	wantErr error
}

func runProtocolTestcase(
	t *testing.T,
	client ClientTransportProtocol,
	tc protocolTestcase,
) {
	t.Helper()
	for _, msg := range tc.in {
		assert.NoError(t, client.Send(t.Context(), msg), fmt.Sprintf("failed to send message for %s", tc.name))
	}

	for _, want := range tc.out {
		checkpoint, err := client.Recv(t.Context())
		if want.wantErr != nil {
			assert.ErrorIs(t, want.wantErr, err, fmt.Sprintf("failed to match expected error for %s", tc.name))
		} else {
			assert.Empty(t, cmp.Diff(
				checkpoint,
				want.msg,
				protocmp.Transform(),
			), fmt.Sprintf("failed to match expected response for %s", tc.name))
		}
	}
}

// recording data

func makeMetadata(id string, md *ssh.RecordingMetadata) *xrecording.RecordingData {
	return &xrecording.RecordingData{
		RecordingId: id,
		Data: &xrecording.RecordingData_Metadata{
			Metadata: &xrecording.RecordingMetadata{
				RecordingType: xrecording.RecordingFormat_RecordingFormatSSH,
				Metadata:      protoutil.NewAny(md),
			},
		},
	}
}

func makeChunkOne(id string, chunk []byte) *xrecording.RecordingData {
	return &xrecording.RecordingData{
		RecordingId: id,
		Data: &xrecording.RecordingData_Chunk{
			Chunk: chunk,
		},
	}
}

func makeChunks(id string, chunks [][]byte) (chunkMsg []*xrecording.RecordingData, checksumMsg *recording.RecordingData) {
	ret := []*xrecording.RecordingData{}
	flattened := []byte{}
	for _, chunk := range chunks {
		ret = append(ret, makeChunkOne(id, chunk))
		flattened = append(flattened, chunk...)
	}
	checksum := md5.Sum(flattened)
	return ret, &xrecording.RecordingData{
		RecordingId: id,
		Data: &xrecording.RecordingData_ChunkMetadata{
			ChunkMetadata: &xrecording.ChunkMetadata{
				Checksum: checksum[:],
			},
		},
	}
}

func makeTrailer(id string, envoyVersion string) *xrecording.RecordingData {
	return &xrecording.RecordingData{
		RecordingId: id,
		Data: &xrecording.RecordingData_Trailer{
			Trailer: &xrecording.RecordingTrailer{
				EnvoyVersion: envoyVersion,
			},
		},
	}
}

// protocol client implementations

type ClientTransportProtocol interface {
	Recv(ctx context.Context) (*xrecording.RecordingCheckpoint, error)
	Send(ctx context.Context, s *xrecording.RecordingData) error
}

type pipeClientTransportProtocol struct {
	uploadWrite   *os.File
	checkointRead protodelim.Reader
}

func newPipeClientTransportProtocol(
	t *testing.T,
	uploadWrite *os.File,
	checkpointRead *os.File,
) ClientTransportProtocol {
	t.Helper()
	_, err := uploadWrite.Write(magicBytes)
	require.NoError(t, err)
	return &pipeClientTransportProtocol{
		uploadWrite:   uploadWrite,
		checkointRead: bufio.NewReader(checkpointRead),
	}
}

func (p *pipeClientTransportProtocol) Recv(_ context.Context) (*xrecording.RecordingCheckpoint, error) {
	return readProtoHelper[*xrecording.RecordingCheckpoint](
		p.checkointRead,
	)
}

func (p *pipeClientTransportProtocol) Send(_ context.Context, s *xrecording.RecordingData) error {
	return sendProtoHelper(p.uploadWrite, []*xrecording.RecordingData{s})
}

var _ ClientTransportProtocol = (*pipeClientTransportProtocol)(nil)

type grpcClientTransportProtocol struct {
	stream grpc.BidiStreamingClient[xrecording.RecordingData, xrecording.RecordingCheckpoint]
}

func newGrpcClientTransport(ctx context.Context, cc grpc.ClientConnInterface) (ClientTransportProtocol, error) {
	stream, err := xrecording.NewRecordingServiceClient(cc).Record(ctx)
	if err != nil {
		return nil, err
	}
	return &grpcClientTransportProtocol{stream: stream}, nil
}

func (g *grpcClientTransportProtocol) Send(_ context.Context, s *xrecording.RecordingData) error {
	return g.stream.Send(s)
}

func (g *grpcClientTransportProtocol) Recv(_ context.Context) (*xrecording.RecordingCheckpoint, error) {
	return g.stream.Recv()
}

var _ ClientTransportProtocol = (*grpcClientTransportProtocol)(nil)
