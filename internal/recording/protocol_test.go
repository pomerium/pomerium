package recording

import (
	"bufio"
	"context"
	"crypto/md5"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gblob "gocloud.dev/blob"
	"gocloud.dev/blob/memblob"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/encoding/protodelim"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/pomerium/envoy-custom/api/x/recording"
	xrecording "github.com/pomerium/envoy-custom/api/x/recording"
	"github.com/pomerium/envoy-custom/api/x/recording/formats/ssh"
	"github.com/pomerium/pomerium/internal/testutil"
	"github.com/pomerium/pomerium/pkg/protoutil"
	"github.com/pomerium/pomerium/pkg/storage/blob"
	"github.com/pomerium/pomerium/pkg/storage/blob/middleware"
	blobtestutil "github.com/pomerium/pomerium/pkg/storage/blob/testutil"
)

func TestRecordingProtocol(t *testing.T) {
	t.Parallel()
	envFactory := map[string]func(*testing.T, uint32) *testRecordingEnv{
		"pipe": NewPipeEnv,
		"grpc": NewGrpcEnv,
	}

	for name, envF := range envFactory {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			testProtocolConformance(t, envF)
		})
	}
}

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

type testRecordingEnv struct {
	ctx                 context.Context
	bucket              *gblob.Bucket
	managedPrefix       string
	clients             []ClientTransportProtocol
	triggerBucketChange func(*gblob.Bucket)
}

// schema returns the SchemaV1WithKey the protocol handler uses for the given
// recording id. Mirrors Handler.openWriter in protocol.go.
func (e *testRecordingEnv) schema(id string) blob.SchemaV1WithKey {
	return blob.NewSchemaV1WithKey(blob.SchemaV1{
		ClusterID:     e.managedPrefix,
		RecordingType: string(blob.RecordingTypeSSH),
	}, id)
}

func NewPipeEnv(t *testing.T, concurrency uint32) *testRecordingEnv {
	t.Helper()
	ctx := t.Context()
	bucket := memblob.OpenBucket(nil)
	pipes, err := SetupRecordingPipes(&ssh.Config{
		UploadConfig: &ssh.UploadConfig{
			Concurrency: &wrapperspb.UInt32Value{
				Value: concurrency,
			},
		},
	})
	require.NoError(t, err)
	require.Len(t, pipes, int(concurrency))
	pipeIPC := NewPipeIPC("Pomerium/v0.0.0+", bucket, "some-prefix", pipes)

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
		ctx:           ctx,
		bucket:        bucket,
		managedPrefix: "some-prefix",
		clients:       clients,
		triggerBucketChange: func(b *gblob.Bucket) {
			for _, p := range pipes {
				p.OnChange(b, "some-prefix")
			}
		},
	}
}

type testServer struct {
	bucket        *gblob.Bucket
	managedPrefix string

	mu         sync.Mutex
	transports []TransportProtocol
}

func (t *testServer) Record(stream grpc.BidiStreamingServer[xrecording.RecordingData, xrecording.RecordingCheckpoint]) error {
	tr := &grpcTransport{stream: stream}
	t.mu.Lock()
	t.transports = append(t.transports, tr)
	t.mu.Unlock()
	ctx := middleware.ContextWithBlobUserAgent(stream.Context(), "Pomerium/v0.0.0+")
	return RunProtocol(ctx, tr, t.bucket, t.managedPrefix)
}

func (t *testServer) fireBucketChange(b *gblob.Bucket) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, tr := range t.transports {
		tr.OnChange(b, t.managedPrefix)
	}
}

var _ xrecording.RecordingServiceServer = (*testServer)(nil)

func NewGrpcEnv(t *testing.T, concurrency uint32) *testRecordingEnv {
	t.Helper()
	bucket := memblob.OpenBucket(nil)
	ctx := middleware.ContextWithBlobUserAgent(t.Context(), "Pomerium/v0.0.0+")
	srv := &testServer{bucket: bucket, managedPrefix: "some-prefix"}
	cc := testutil.NewGRPCServer(t, func(s *grpc.Server) {
		s.RegisterService(&xrecording.RecordingService_ServiceDesc, srv)
	})

	clients := []ClientTransportProtocol{}
	for range concurrency {
		c, err := newGrpcClientTransport(ctx, cc)
		require.NoError(t, err)
		clients = append(clients, c)
	}
	return &testRecordingEnv{
		ctx:                 ctx,
		bucket:              bucket,
		managedPrefix:       "some-prefix",
		clients:             clients,
		triggerBucketChange: srv.fireBucketChange,
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

func testProtocolConformance(t *testing.T, envF func(*testing.T, uint32) *testRecordingEnv) {
	t.Run("simple successful upload", func(t *testing.T) {
		env := envF(t, 1)
		client := env.clients[0]

		fooMetadata := makeMetadata("foo", &ssh.RecordingMetadata{ProtocolVersion: uint32(42)})
		fooChunks, fooChecksum := makeChunks("foo", [][]byte{[]byte("chunk1"), []byte("chunk2"), []byte("chunk3")})
		tcs := []protocolTestcase{
			{
				name: "metadata handshake",
				in:   []*xrecording.RecordingData{fooMetadata},
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

		fooSchema := env.schema("foo")
		fooManifest := &xrecording.ChunkManifest{
			Items: []*xrecording.ChunkMetadata{
				{Size: 18, Checksum: fooChecksum.GetChecksum()},
			},
		}
		blobtestutil.TestFullObjectMatches(t, env.bucket, fooSchema,
			fooMetadata,
			fooManifest,
			[]byte("chunk1chunk2chunk3"),
			&xrecording.RecordingTrailer{EnvoyVersion: "Envoy v0.0.0+"},
		)
		blobtestutil.TestSchemaIDsMatchExactly(t, env.bucket, fooSchema.SchemaV1, []string{"foo"})
	})

	t.Run("resume support", func(t *testing.T) {
		env := envF(t, 1)
		client := env.clients[0]

		fooMetadata := makeMetadata("foo", &ssh.RecordingMetadata{ProtocolVersion: 42})
		firstChunks, firstChecksum := makeChunks("foo", [][]byte{[]byte("first-chunk")})
		firstSize := uint32(len("first-chunk"))
		firstManifest := &xrecording.ChunkManifest{
			Items: []*xrecording.ChunkMetadata{
				{Size: firstSize, Checksum: firstChecksum.GetChecksum()},
			},
		}

		secondChunks, secondChecksum := makeChunks("foo", [][]byte{[]byte("second-chunk")})
		secondSize := uint32(len("second-chunk"))
		resumedManifest := &xrecording.ChunkManifest{
			Items: []*xrecording.ChunkMetadata{
				{Size: firstSize, Checksum: firstChecksum.GetChecksum()},
				{Size: secondSize, Checksum: secondChecksum.GetChecksum()},
			},
		}

		tcs := []protocolTestcase{
			{
				name: "metadata handshake",
				in:   []*xrecording.RecordingData{fooMetadata},
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
				name: "upload first chunk",
				in:   append(firstChunks, firstChecksum),
				out: []testcaseRecv{
					{
						msg: &xrecording.RecordingCheckpoint{
							RecordingId: "foo",
							Manifest:    firstManifest,
						},
					},
				},
			},
			{
				name: "re-initiated handshake returns prior manifest",
				in:   []*xrecording.RecordingData{fooMetadata},
				out: []testcaseRecv{
					{
						msg: &xrecording.RecordingCheckpoint{
							RecordingId: "foo",
							Manifest:    firstManifest,
						},
					},
				},
			},
			{
				name: "upload second chunk after resume",
				in:   append(secondChunks, secondChecksum),
				out: []testcaseRecv{
					{
						msg: &xrecording.RecordingCheckpoint{
							RecordingId: "foo",
							Manifest:    resumedManifest,
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
							Manifest:    resumedManifest,
						},
					},
				},
			},
		}
		for _, tc := range tcs {
			runProtocolTestcase(t, client, tc)
		}

		fooSchema := env.schema("foo")
		blobtestutil.TestFullObjectMatches(t, env.bucket, fooSchema,
			fooMetadata,
			resumedManifest,
			[]byte("first-chunksecond-chunk"),
			&xrecording.RecordingTrailer{EnvoyVersion: "Envoy v0.0.0+"},
		)
		blobtestutil.TestSchemaIDsMatchExactly(t, env.bucket, fooSchema.SchemaV1, []string{"foo"})
	})

	t.Run("interleaved recordings upload", func(t *testing.T) {
		env := envF(t, 1)
		client := env.clients[0]

		fooMetadata := makeMetadata("foo", &ssh.RecordingMetadata{ProtocolVersion: uint32(42)})
		barMetadata := makeMetadata("bar", &ssh.RecordingMetadata{ProtocolVersion: uint32(42)})

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

		var fooFull, barFull []byte
		for _, c := range fooChunkBytes {
			fooFull = append(fooFull, c...)
		}
		for _, c := range barChunkBytes {
			barFull = append(barFull, c...)
		}
		fooSize := uint32(len(fooFull))
		barSize := uint32(len(barFull))

		tcs := []protocolTestcase{
			{
				name: "metadata handshake",
				in:   []*xrecording.RecordingData{fooMetadata, barMetadata},
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

		trailer := &xrecording.RecordingTrailer{EnvoyVersion: "Envoy v0.0.0+"}
		fooSchema := env.schema("foo")
		fooManifest := &xrecording.ChunkManifest{
			Items: []*xrecording.ChunkMetadata{
				{Size: fooSize, Checksum: fooChecksum.GetChecksum()},
			},
		}
		blobtestutil.TestFullObjectMatches(t, env.bucket, fooSchema, fooMetadata, fooManifest, fooFull, trailer)

		barSchema := env.schema("bar")
		barManifest := &xrecording.ChunkManifest{
			Items: []*xrecording.ChunkMetadata{
				{Size: barSize, Checksum: barChecksum.GetChecksum()},
			},
		}
		blobtestutil.TestFullObjectMatches(t, env.bucket, barSchema, barMetadata, barManifest, barFull, trailer)

		blobtestutil.TestSchemaIDsMatchExactly(t, env.bucket, fooSchema.SchemaV1, []string{"foo", "bar"})
	})

	t.Run("bucket change signals client restart", func(t *testing.T) {
		conc := uint32(1)
		env := envF(t, conc)
		client := env.clients[0]

		initialChunks, initialChecksum := makeChunks("foo", [][]byte{[]byte("before-change")})
		initialSize := uint32(len("before-change"))
		setup := []protocolTestcase{
			{
				name: "initial metadata handshake",
				in: []*xrecording.RecordingData{
					makeMetadata("foo", &ssh.RecordingMetadata{ProtocolVersion: 42}),
				},
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
				name: "initial chunk upload",
				in:   append(initialChunks, initialChecksum),
				out: []testcaseRecv{
					{
						msg: &xrecording.RecordingCheckpoint{
							RecordingId: "foo",
							Manifest: &xrecording.ChunkManifest{
								Items: []*xrecording.ChunkMetadata{
									{
										Size:     initialSize,
										Checksum: initialChecksum.GetChecksum(),
									},
								},
							},
						},
					},
				},
			},
		}
		for _, tc := range setup {
			runProtocolTestcase(t, client, tc)
		}

		initialObjDir := env.schema("foo").ObjectDir()
		blobtestutil.TestFullPathsMatchExactly(t, env.bucket, []string{
			initialObjDir + "/metadata.proto",
			initialObjDir + "/metadata.json",
			initialObjDir + "/recording_0000000000.json",
		})
		blobtestutil.TestSchemaIDsMatchExactly(t, env.bucket, env.schema("").SchemaV1, []string{"foo"})

		newBucket := memblob.OpenBucket(nil)
		env.triggerBucketChange(newBucket)

		afterChunks, afterChecksum := makeChunks("foo", [][]byte{[]byte("after-change")})
		afterSize := uint32(len("after-change"))
		tcs := []protocolTestcase{
			{
				name: "checksum after bucket change is rejected without prior metadata",
				in:   []*xrecording.RecordingData{afterChecksum},
				out: []testcaseRecv{
					{
						msg: &xrecording.RecordingCheckpoint{
							RecordingId: "foo",
							Status:      errorStatus(ErrMissingMetadata),
						},
					},
				},
			},
			{
				name: "client re-handshakes against the new bucket",
				in: []*xrecording.RecordingData{
					makeMetadata("foo", &ssh.RecordingMetadata{ProtocolVersion: 42}),
				},
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
				name: "upload succeeds against the new bucket",
				in:   append(afterChunks, afterChecksum),
				out: []testcaseRecv{
					{
						msg: &xrecording.RecordingCheckpoint{
							RecordingId: "foo",
							Manifest: &xrecording.ChunkManifest{
								Items: []*xrecording.ChunkMetadata{
									{
										Size:     afterSize,
										Checksum: afterChecksum.GetChecksum(),
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

		// original bucket untouched after the swap — nothing new appended
		blobtestutil.TestFullPathsMatchExactly(t, env.bucket, []string{
			initialObjDir + "/metadata.proto",
			initialObjDir + "/metadata.json",
			initialObjDir + "/recording_0000000000.json",
		})
		// new bucket received only the post-swap writes for the re-handshake
		blobtestutil.TestFullPathsMatchExactly(t, newBucket, []string{
			initialObjDir + "/metadata.proto",
			initialObjDir + "/metadata.json",
			initialObjDir + "/recording_0000000000.json",
		})
		blobtestutil.TestSchemaIDsMatchExactly(t, newBucket, env.schema("").SchemaV1, []string{"foo"})
	})

	t.Run("multi-plexed transport upload", func(t *testing.T) {
		conc := uint32(8)
		env := envF(t, conc)
		require.Len(t, env.clients, int(conc))

		expectedIDs := make([]string, 0, conc)
		for i := range int(conc) {
			expectedIDs = append(expectedIDs, fmt.Sprintf("rec-%d", i))
		}

		var wg sync.WaitGroup
		for i, client := range env.clients {
			wg.Go(func() {
				id := fmt.Sprintf("rec-%d", i)
				metadata := makeMetadata(id, &ssh.RecordingMetadata{ProtocolVersion: 42})
				chunks, checksum := makeChunks(id, [][]byte{
					[]byte("chunk1"), []byte("chunk2"), []byte("chunk3"),
				})
				expectedManifest := &xrecording.ChunkManifest{
					Items: []*xrecording.ChunkMetadata{
						{Size: 18, Checksum: checksum.GetChecksum()},
					},
				}
				tcs := []protocolTestcase{
					{
						name: id + " metadata handshake",
						in:   []*xrecording.RecordingData{metadata},
						out: []testcaseRecv{
							{
								msg: &xrecording.RecordingCheckpoint{
									RecordingId: id,
									Manifest:    &xrecording.ChunkManifest{},
								},
							},
						},
					},
					{
						name: id + " chunk upload",
						in:   append(chunks, checksum),
						out: []testcaseRecv{
							{
								msg: &xrecording.RecordingCheckpoint{
									RecordingId: id,
									Manifest:    expectedManifest,
								},
							},
						},
					},
					{
						name: id + " finalize",
						in: []*xrecording.RecordingData{
							makeTrailer(id, "Envoy v0.0.0+"),
						},
						out: []testcaseRecv{
							{
								msg: &xrecording.RecordingCheckpoint{
									RecordingId: id,
									Manifest:    expectedManifest,
								},
							},
						},
					},
				}
				for _, tc := range tcs {
					runProtocolTestcase(t, client, tc)
				}

				blobtestutil.TestFullObjectMatches(t, env.bucket, env.schema(id),
					metadata,
					expectedManifest,
					[]byte("chunk1chunk2chunk3"),
					&xrecording.RecordingTrailer{EnvoyVersion: "Envoy v0.0.0+"},
				)
			})
		}
		wg.Wait()

		blobtestutil.TestSchemaIDsMatchExactly(t, env.bucket, env.schema("").SchemaV1, expectedIDs)
	})

	t.Run("protocol failures", func(t *testing.T) {
		t.Run("metadata not sent before chunk/trailers", func(t *testing.T) {
			env := envF(t, 1)
			client := env.clients[0]

			tcs := []protocolTestcase{
				{
					name: "chunk before metadata",
					in: []*xrecording.RecordingData{
						makeChunkOne("chunk-first", []byte("payload")),
					},
					out: []testcaseRecv{
						{
							msg: &xrecording.RecordingCheckpoint{
								RecordingId: "chunk-first",
								Status:      errorStatus(ErrMissingMetadata),
							},
						},
					},
				},
				{
					name: "checksum before metadata",
					in: []*xrecording.RecordingData{
						{
							RecordingId: "checksum-first",
							Data: &xrecording.RecordingData_Checksum{
								Checksum: make([]byte, 16),
							},
						},
					},
					out: []testcaseRecv{
						{
							msg: &xrecording.RecordingCheckpoint{
								RecordingId: "checksum-first",
								Status:      errorStatus(ErrMissingMetadata),
							},
						},
					},
				},
				{
					name: "trailer before metadata",
					in: []*xrecording.RecordingData{
						makeTrailer("trailer-first", "Envoy v0.0.0+"),
					},
					out: []testcaseRecv{
						{
							msg: &xrecording.RecordingCheckpoint{
								RecordingId: "trailer-first",
								Status:      errorStatus(ErrMissingMetadata),
							},
						},
					},
				},
			}
			for _, tc := range tcs {
				runProtocolTestcase(t, client, tc)
			}
		})

		t.Run("invalid metadata", func(t *testing.T) {
			env := envF(t, 1)
			client := env.clients[0]

			runProtocolTestcase(t, client, protocolTestcase{
				name: "unknown recording type is rejected",
				in: []*xrecording.RecordingData{
					{
						RecordingId: "foo",
						Data: &xrecording.RecordingData_Metadata{
							Metadata: &xrecording.RecordingMetadata{
								RecordingType: xrecording.RecordingFormat_RecordingFormatUnknown,
								Metadata:      protoutil.NewAny(&ssh.RecordingMetadata{ProtocolVersion: 42}),
							},
						},
					},
				},
				out: []testcaseRecv{
					{
						msg: &xrecording.RecordingCheckpoint{
							RecordingId: "foo",
							Status: errorStatus(fmt.Errorf(
								"%w: invalid recording type: %s",
								ErrInvalidMetadata,
								xrecording.RecordingFormat_RecordingFormatUnknown,
							)),
						},
					},
				},
			})
		})

		t.Run("metadata conflict", func(t *testing.T) {
			env := envF(t, 1)
			client := env.clients[0]

			tcs := []protocolTestcase{
				{
					name: "first metadata accepted",
					in: []*xrecording.RecordingData{
						makeMetadata("foo", &ssh.RecordingMetadata{ProtocolVersion: 42}),
					},
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
					name: "conflicting metadata rejected",
					in: []*xrecording.RecordingData{
						makeMetadata("foo", &ssh.RecordingMetadata{ProtocolVersion: 99}),
					},
					out: []testcaseRecv{
						{
							msg: &xrecording.RecordingCheckpoint{
								RecordingId: "foo",
								Manifest:    &xrecording.ChunkManifest{},
								Status:      errorStatus(blob.ErrMetadataMismatch),
							},
						},
					},
				},
			}
			for _, tc := range tcs {
				runProtocolTestcase(t, client, tc)
			}
		})

		t.Run("messages missing recording ID", func(t *testing.T) {
			env := envF(t, 1)
			client := env.clients[0]

			tcs := []protocolTestcase{
				{
					name: "metadata without recording id",
					in: []*xrecording.RecordingData{
						{
							Data: &xrecording.RecordingData_Metadata{
								Metadata: &xrecording.RecordingMetadata{
									RecordingType: xrecording.RecordingFormat_RecordingFormatSSH,
									Metadata:      protoutil.NewAny(&ssh.RecordingMetadata{ProtocolVersion: 42}),
								},
							},
						},
					},
					out: []testcaseRecv{
						{
							msg: &xrecording.RecordingCheckpoint{
								Status: errorStatus(ErrMissingRecordingID),
							},
						},
					},
				},
				{
					name: "chunk without recording id",
					in: []*xrecording.RecordingData{
						makeChunkOne("", []byte("payload")),
					},
					out: []testcaseRecv{
						{
							msg: &xrecording.RecordingCheckpoint{
								Status: errorStatus(ErrMissingRecordingID),
							},
						},
					},
				},
				{
					name: "trailer without recording id",
					in: []*xrecording.RecordingData{
						makeTrailer("", "Envoy v0.0.0+"),
					},
					out: []testcaseRecv{
						{
							msg: &xrecording.RecordingCheckpoint{
								Status: errorStatus(ErrMissingRecordingID),
							},
						},
					},
				},
			}
			for _, tc := range tcs {
				runProtocolTestcase(t, client, tc)
			}
		})
	})
}
