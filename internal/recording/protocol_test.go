package recording

import (
	"bufio"
	"context"
	"crypto/md5"
	"errors"
	"fmt"
	"io"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/pomerium/envoy-custom/api/x/recording"
	xrecording "github.com/pomerium/envoy-custom/api/x/recording"
	"github.com/pomerium/envoy-custom/api/x/recording/formats/ssh"
	"github.com/pomerium/pomerium/pkg/protoutil"
	"github.com/pomerium/pomerium/pkg/storage/blob/middleware"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gblob "gocloud.dev/blob"
	"gocloud.dev/blob/memblob"
	"google.golang.org/protobuf/encoding/protodelim"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type ClientTransportProtocol interface {
	Recv(ctx context.Context) (*xrecording.RecordingCheckpoint, error)
	Send(ctx context.Context, s *xrecording.RecordingData) error
}

type pipeClientTransportProtocol struct {
	uploadWrite   *os.File
	checkointRead protodelim.Reader
}

func newPipeClientTransportProtocol(
	uploadWrite *os.File,
	checkpointRead *os.File,
) ClientTransportProtocol {
	return &pipeClientTransportProtocol{
		uploadWrite:   uploadWrite,
		checkointRead: bufio.NewReader(checkpointRead),
	}
}

func (p *pipeClientTransportProtocol) Recv(ctx context.Context) (*xrecording.RecordingCheckpoint, error) {
	return readProtoHelper[*xrecording.RecordingCheckpoint](
		p.checkointRead,
	)
}

func (p *pipeClientTransportProtocol) Send(ctx context.Context, s *xrecording.RecordingData) error {
	return sendProtoHelper(p.uploadWrite, []*xrecording.RecordingData{s})
}

var _ ClientTransportProtocol = (*pipeClientTransportProtocol)(nil)

type testRecordingEnv struct {
	ctx     context.Context
	bucket  *gblob.Bucket
	clients []ClientTransportProtocol
}

func NewTestRecordingEnv(t *testing.T, concurrency uint32) *testRecordingEnv {
	t.Helper()
	ctx := middleware.ContextWithBlobUserAgent(t.Context(), "Pomerium/v0.0.0+")
	bucket := memblob.OpenBucket(nil)
	pipes, err := SetupRecordingPipes(&ssh.Config{
		UploadConfig: &ssh.UploadConfig{
			Concurrency: &wrapperspb.UInt32Value{
				Value: concurrency,
			},
		},
	})
	require.NoError(t, err)
	require.Len(t, pipes, 1)
	pipeIPC := NewPipeIPC(bucket, "some-prefix", pipes)

	errC := make(chan error, 1)
	go func() {
		errC <- pipeIPC.Serve(ctx)
	}()
	t.Cleanup(func() {
		_ = pipeIPC.Close()
		serveErr := <-errC
		if !errors.Is(serveErr, io.EOF) &&
			!errors.Is(serveErr, os.ErrClosed) &&
			!errors.Is(serveErr, context.Canceled) {
			t.Fatalf("serve returned unexpected error: %v", serveErr)
		}
	})
	clients := []ClientTransportProtocol{}
	for _, pipe := range pipes {
		clients = append(clients, newPipeClientTransportProtocol(
			pipe.uploadWrite,
			pipe.checkpointRead,
		))
	}
	return &testRecordingEnv{
		ctx:     ctx,
		bucket:  bucket,
		clients: clients,
	}
}

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
	tc protocolTestcase) {
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
		Data: &xrecording.RecordingData_Checksum{
			Checksum: checksum[:],
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

func TestRecordingProtocol(t *testing.T) {
	t.Run("simple successful upload", func(t *testing.T) {
		env := NewTestRecordingEnv(t, 1)
		client := env.clients[0]

		fooChunks, fooChecksum := makeChunks("foo", [][]byte{[]byte("chunk1"), []byte("chunk2"), []byte("chunk3")})
		tcs := []protocolTestcase{
			{
				name: "metadata handshake",
				in: []*xrecording.RecordingData{makeMetadata("foo", &ssh.RecordingMetadata{
					ProtocolVersion: uint32(42),
				})},
				out: []testcaseRecv{
					{
						msg: &xrecording.RecordingCheckpoint{
							RecordingId: "foo",
							Manifest:    &xrecording.ChunkManifest{},
						},
					},
				},
			},
			{
				name: "chunk upload step",
				in:   append(fooChunks, fooChecksum),
				out: []testcaseRecv{
					{
						msg: &xrecording.RecordingCheckpoint{
							RecordingId: "foo",
							Manifest: &xrecording.ChunkManifest{
								Items: []*xrecording.ChunkMetadata{
									{
										Size:     18,
										Checksum: fooChecksum.GetChecksum(),
									},
								},
							},
						},
					},
				},
			},
			{
				name: "finalize recording",
				in: []*xrecording.RecordingData{
					makeTrailer("foo", "Envoy v0.0.0+"),
				},
				out: []testcaseRecv{
					{
						msg: &xrecording.RecordingCheckpoint{
							RecordingId: "foo",
							Manifest: &xrecording.ChunkManifest{
								Items: []*xrecording.ChunkMetadata{
									{
										Size:     18,
										Checksum: fooChecksum.GetChecksum(),
									},
								},
							},
						},
					},
				},
			},
		}
		for _, tc := range tcs {
			runProtocolTestcase(t, client, tc)
		}
	})

	t.Run("resume support", func(t *testing.T) {

	})

	t.Run("interleaved recordings upload", func(t *testing.T) {
		env := NewTestRecordingEnv(t, 1)
		client := env.clients[0]

		numChunks := 5
		fooChunkBytes := make([][]byte, 0, numChunks)
		barChunkBytes := make([][]byte, 0, numChunks)
		interleavedChunks := []*xrecording.RecordingData{}
		for i := range numChunks {
			fooChunk := fmt.Appendf(nil, "chunkc_foo_ %d", i)
			barChunk := fmt.Appendf(nil, "chunkc_bar_ %d", i)
			fooChunkBytes = append(fooChunkBytes, fooChunk)
			barChunkBytes = append(barChunkBytes, barChunk)
			interleavedChunks = append(interleavedChunks,
				makeChunkOne("foo", fooChunk),
				makeChunkOne("bar", barChunk),
			)
		}
		_, fooChecksum := makeChunks("foo", fooChunkBytes)
		_, barChecksum := makeChunks("bar", barChunkBytes)

		var fooSize, barSize uint32
		for _, c := range fooChunkBytes {
			fooSize += uint32(len(c))
		}
		for _, c := range barChunkBytes {
			barSize += uint32(len(c))
		}

		tcs := []protocolTestcase{
			{
				name: "metadata handshake",
				in: []*xrecording.RecordingData{
					makeMetadata("foo", &ssh.RecordingMetadata{ProtocolVersion: uint32(42)}),
					makeMetadata("bar", &ssh.RecordingMetadata{ProtocolVersion: uint32(42)}),
				},
				out: []testcaseRecv{
					{
						msg: &xrecording.RecordingCheckpoint{
							RecordingId: "foo",
							Manifest:    &xrecording.ChunkManifest{},
						},
					},
					{
						msg: &xrecording.RecordingCheckpoint{
							RecordingId: "bar",
							Manifest:    &xrecording.ChunkManifest{},
						},
					},
				},
			},
			{
				name: "interleaved chunks followed by bar checksum",
				in:   append(interleavedChunks, barChecksum),
				out: []testcaseRecv{
					{
						msg: &xrecording.RecordingCheckpoint{
							RecordingId: "bar",
							Manifest: &xrecording.ChunkManifest{
								Items: []*xrecording.ChunkMetadata{
									{
										Size:     barSize,
										Checksum: barChecksum.GetChecksum(),
									},
								},
							},
						},
					},
				},
			},
			{
				name: "foo checksum",
				in:   []*xrecording.RecordingData{fooChecksum},
				out: []testcaseRecv{
					{
						msg: &xrecording.RecordingCheckpoint{
							RecordingId: "foo",
							Manifest: &xrecording.ChunkManifest{
								Items: []*xrecording.ChunkMetadata{
									{
										Size:     fooSize,
										Checksum: fooChecksum.GetChecksum(),
									},
								},
							},
						},
					},
				},
			},
			{
				name: "finalize foo",
				in: []*xrecording.RecordingData{
					makeTrailer("foo", "Envoy v0.0.0+"),
				},
				out: []testcaseRecv{
					{
						msg: &xrecording.RecordingCheckpoint{
							RecordingId: "foo",
							Manifest: &xrecording.ChunkManifest{
								Items: []*xrecording.ChunkMetadata{
									{
										Size:     fooSize,
										Checksum: fooChecksum.GetChecksum(),
									},
								},
							},
						},
					},
				},
			},
			{
				name: "finalize bar",
				in: []*xrecording.RecordingData{
					makeTrailer("bar", "Envoy v0.0.0+"),
				},
				out: []testcaseRecv{
					{
						msg: &xrecording.RecordingCheckpoint{
							RecordingId: "bar",
							Manifest: &xrecording.ChunkManifest{
								Items: []*xrecording.ChunkMetadata{
									{
										Size:     barSize,
										Checksum: barChecksum.GetChecksum(),
									},
								},
							},
						},
					},
				},
			},
		}
		for _, tc := range tcs {
			runProtocolTestcase(t, client, tc)
		}
	})

	t.Run("multi-plexed transport upload", func(t *testing.T) {
		conc := uint32(8)
		env := NewTestRecordingEnv(t, conc)
		fmt.Println(env)
	})

	t.Run("protocol failures", func(t *testing.T) {
		t.Run("metadata never received by server", func(t *testing.T) {
			env := NewTestRecordingEnv(t, 1)
			ctx := env.ctx
			client := env.clients[0]

			err := client.Send(ctx, &xrecording.RecordingData{
				RecordingId: "foo",
				Data: &xrecording.RecordingData_Chunk{
					Chunk: []byte("payload"),
				},
			})
			require.NoError(t, err)

			// TODO : this doesn't receive anything
			resp, err := client.Recv(ctx)
			assert.Error(t, err)
			assert.ErrorIs(t, err, ErrMissingMetadata)
			assert.Nil(t, resp)
		})

		t.Run("invalid metadata", func(t *testing.T) {
			env := NewTestRecordingEnv(t, 1)
			fmt.Println(env)
			// TODO :
		})

		t.Run("messages missing recording ID", func(t *testing.T) {
			env := NewTestRecordingEnv(t, 1)
			fmt.Println(env)

		})

		t.Run("upload failed", func(t *testing.T) {
			// TODO :
			env := NewTestRecordingEnv(t, 1)
			fmt.Println(env)

		})
	})

	t.Run("per-recording failures in interleaved upload", func(t *testing.T) {
		t.Run("metadata never received by server", func(t *testing.T) {
			env := NewTestRecordingEnv(t, 1)
			fmt.Println(env)
		})

		t.Run("invalid metadata", func(t *testing.T) {
			env := NewTestRecordingEnv(t, 1)
			fmt.Println(env)
			// TODO :
		})

		t.Run("messages missing recording ID", func(t *testing.T) {
			env := NewTestRecordingEnv(t, 1)
			fmt.Println(env)

		})

		t.Run("upload failed", func(t *testing.T) {
			// TODO :
			env := NewTestRecordingEnv(t, 1)
			fmt.Println(env)

		})
	})

	t.Run("global failures in upload", func(t *testing.T) {
		// failures that require a protocol handshake reset
		t.Run("bucket close", func(t *testing.T) {

		})

		t.Run("shutdown ipc mode", func(t *testing.T) {

		})

	})
}
