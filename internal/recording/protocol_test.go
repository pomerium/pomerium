package recording

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/envoy-custom/api/x/recording"
	xrecording "github.com/pomerium/envoy-custom/api/x/recording"
	"github.com/pomerium/envoy-custom/api/x/recording/formats/ssh"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/pkg/ipc"
	"github.com/pomerium/pomerium/pkg/protoutil"
	"github.com/pomerium/pomerium/pkg/storage/blob"
	"github.com/pomerium/pomerium/pkg/storage/blob/providers"
	blobtestutil "github.com/pomerium/pomerium/pkg/storage/blob/testutil"
)

func TestRecordingProtocol(t *testing.T) {
	t.Parallel()
	envFactory := map[string]func(*testing.T, uint32) *testRecordingEnv{
		"pipe": NewPipeEnv,
	}

	for name, envF := range envFactory {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			testProtocolConformance(t, envF)
		})
	}
}

type testRecordingEnv struct {
	handler       *Handler
	ctx           context.Context
	managedPrefix string
	clients       []ClientTransportProtocol
	server        Server
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
	workers, err := ipc.NewPipeWorkers[*recording.RecordingData, *recording.RecordingCheckpoint](int(concurrency))
	require.NoError(t, err)
	require.Len(t, workers, int(concurrency))
	server, err := NewRecordingServer(ctx, &config.Config{}, workers)
	require.NoError(t, err)

	errC := make(chan error, 1)
	go func() {
		errC <- server.Serve(ctx)
	}()
	t.Cleanup(func() {
		_ = server.Shutdown(t.Context())
		serveErr := <-errC
		assert.NoError(t, serveErr)
	})
	clients := []ClientTransportProtocol{}
	for _, worker := range workers {
		clients = append(clients, newPipeClientTransportProtocol(
			t,
			worker,
		))
	}
	env := &testRecordingEnv{
		ctx:           ctx,
		clients:       clients,
		managedPrefix: "test-prefix",
		server:        server,
	}
	env.server.OnConfigChange(ctx, &config.Config{
		Options: &config.Options{
			BlobStorage: &blob.StorageConfig{
				BucketURI:     fmt.Sprintf("mem://%s", uuid.New().String()),
				ManagedPrefix: env.managedPrefix,
			},
		},
	})
	return env
}

func testProtocolConformance(t *testing.T, envF func(*testing.T, uint32) *testRecordingEnv) {
	t.Run("simple successful upload", func(t *testing.T) {
		env := envF(t, 1)
		client := env.clients[0]
		require.NoError(t, client.recvHandshake())

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
										Checksum: fooChecksum.GetChunkMetadata().GetChecksum(),
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
										Checksum: fooChecksum.GetChunkMetadata().GetChecksum(),
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
				{Size: 18, Checksum: fooChecksum.GetChunkMetadata().GetChecksum()},
			},
		}

		bucket, _, err := LoadStreamConfigForTest(env.server)
		require.NoError(t, err)
		blobtestutil.TestFullObjectMatches(t, bucket, fooSchema,
			fooMetadata,
			fooManifest,
			[]byte("chunk1chunk2chunk3"),
			&xrecording.RecordingTrailer{EnvoyVersion: "Envoy v0.0.0+"},
		)
		blobtestutil.TestSchemaIDsMatchExactly(t, bucket, fooSchema.SchemaV1, []string{"foo"})
	})

	t.Run("resume support", func(t *testing.T) {
		env := envF(t, 1)
		client := env.clients[0]
		require.NoError(t, client.recvHandshake())

		fooMetadata := makeMetadata("foo", &ssh.RecordingMetadata{ProtocolVersion: 42})
		firstChunks, firstChecksum := makeChunks("foo", [][]byte{[]byte("first-chunk")})
		firstSize := uint32(len("first-chunk"))
		firstManifest := &xrecording.ChunkManifest{
			Items: []*xrecording.ChunkMetadata{
				{Size: firstSize, Checksum: firstChecksum.GetChunkMetadata().GetChecksum()},
			},
		}

		secondChunks, secondChecksum := makeChunks("foo", [][]byte{[]byte("second-chunk")})
		secondSize := uint32(len("second-chunk"))
		resumedManifest := &xrecording.ChunkManifest{
			Items: []*xrecording.ChunkMetadata{
				{Size: firstSize, Checksum: firstChecksum.GetChunkMetadata().GetChecksum()},
				{Size: secondSize, Checksum: secondChecksum.GetChunkMetadata().GetChecksum()},
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
		bucket, _, err := LoadStreamConfigForTest(env.server)
		require.NoError(t, err)
		blobtestutil.TestFullObjectMatches(t, bucket, fooSchema,
			fooMetadata,
			resumedManifest,
			[]byte("first-chunksecond-chunk"),
			&xrecording.RecordingTrailer{EnvoyVersion: "Envoy v0.0.0+"},
		)
		blobtestutil.TestSchemaIDsMatchExactly(t, bucket, fooSchema.SchemaV1, []string{"foo"})
	})

	t.Run("interleaved recordings upload", func(t *testing.T) {
		env := envF(t, 1)
		client := env.clients[0]
		require.NoError(t, client.recvHandshake())

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
										Checksum: barChecksum.GetChunkMetadata().GetChecksum(),
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
										Checksum: fooChecksum.GetChunkMetadata().GetChecksum(),
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
										Checksum: fooChecksum.GetChunkMetadata().GetChecksum(),
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
										Checksum: barChecksum.GetChunkMetadata().GetChecksum(),
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
				{Size: fooSize, Checksum: fooChecksum.GetChunkMetadata().GetChecksum()},
			},
		}
		bucket, _, err := LoadStreamConfigForTest(env.server)
		require.NoError(t, err)
		blobtestutil.TestFullObjectMatches(t, bucket, fooSchema, fooMetadata, fooManifest, fooFull, trailer)

		barSchema := env.schema("bar")
		barManifest := &xrecording.ChunkManifest{
			Items: []*xrecording.ChunkMetadata{
				{Size: barSize, Checksum: barChecksum.GetChunkMetadata().GetChecksum()},
			},
		}
		blobtestutil.TestFullObjectMatches(t, bucket, barSchema, barMetadata, barManifest, barFull, trailer)
		blobtestutil.TestSchemaIDsMatchExactly(t, bucket, fooSchema.SchemaV1, []string{"foo", "bar"})
	})

	t.Run("bucket change signals client restart", func(t *testing.T) {
		conc := uint32(2)
		env := envF(t, conc)
		oldBucketURI := fmt.Sprintf("file://%s", t.TempDir())
		env.server.OnConfigChange(t.Context(), &config.Config{
			Options: &config.Options{
				BlobStorage: &blob.StorageConfig{
					BucketURI:     oldBucketURI,
					ManagedPrefix: env.managedPrefix,
				},
			},
		})

		var wg sync.WaitGroup

		for i, client := range env.clients {
			wg.Go(func() {
				require.NoError(t, client.recvHandshake())
				id := fmt.Sprintf("rec-%d", i)
				initialChunks, initialChecksum := makeChunks(id, [][]byte{[]byte("before-change")})
				initialSize := uint32(len("before-change"))
				setup := []protocolTestcase{
					{
						name: "initial metadata handshake",
						in: []*xrecording.RecordingData{
							makeMetadata(id, &ssh.RecordingMetadata{ProtocolVersion: 42}),
						},
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
						name: "initial chunk upload",
						in:   append(initialChunks, initialChecksum),
						out: []testcaseRecv{
							{
								msg: &xrecording.RecordingCheckpoint{
									RecordingId: id,
									Manifest: &xrecording.ChunkManifest{
										Items: []*xrecording.ChunkMetadata{
											{
												Size:     initialSize,
												Checksum: initialChecksum.GetChunkMetadata().GetChecksum(),
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
			})
		}
		wg.Wait()
		expectedObjs := []string{}
		for i := range env.clients {
			id := fmt.Sprintf("rec-%d", i)
			initialObjDir := env.schema(id).ObjectDir()
			expectedObjs = append(
				expectedObjs,
				initialObjDir+"/metadata.proto",
				initialObjDir+"/metadata.json",
				initialObjDir+"/recording_0000000000",
			)
		}
		bucket, _, err := LoadStreamConfigForTest(env.server)
		require.NoError(t, err)
		blobtestutil.TestFullPathsMatchExactly(t, bucket, expectedObjs)
		blobtestutil.TestSchemaIDsMatchExactly(t, bucket, env.schema("").SchemaV1, []string{"rec-0", "rec-1"})

		env.server.OnConfigChange(t.Context(), &config.Config{
			Options: &config.Options{
				BlobStorage: &blob.StorageConfig{
					BucketURI:     fmt.Sprintf("mem://%s", uuid.New().String()),
					ManagedPrefix: env.managedPrefix,
				},
			},
		})

		for i, client := range env.clients {
			id := fmt.Sprintf("rec-%d", i)
			wg.Go(func() {
				afterChunks, afterChecksum := makeChunks(id, [][]byte{[]byte("after-change")})
				afterSize := uint32(len("after-change"))
				tcs := []protocolTestcase{
					{
						name: "checksum after bucket change is rejected without prior metadata",
						in:   []*xrecording.RecordingData{afterChecksum},
						out: []testcaseRecv{
							{
								msg: &xrecording.RecordingCheckpoint{
									RecordingId: id,
									Status:      errorStatus(ErrMissingMetadata),
								},
							},
						},
					},
					{
						name: "client re-handshakes against the new bucket",
						in: []*xrecording.RecordingData{
							makeMetadata(id, &ssh.RecordingMetadata{ProtocolVersion: 42}),
						},
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
						name: "upload succeeds against the new bucket",
						in:   append(afterChunks, afterChecksum),
						out: []testcaseRecv{
							{
								msg: &xrecording.RecordingCheckpoint{
									RecordingId: id,
									Manifest: &xrecording.ChunkManifest{
										Items: []*xrecording.ChunkMetadata{
											{
												Size:     afterSize,
												Checksum: afterChecksum.GetChunkMetadata().GetChecksum(),
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
		}

		expectedObjs = []string{}
		for i := range env.clients {
			id := fmt.Sprintf("rec-%d", i)
			initialObjDir := env.schema(id).ObjectDir()
			expectedObjs = append(
				expectedObjs,
				initialObjDir+"/metadata.proto",
				initialObjDir+"/metadata.json",
				initialObjDir+"/recording_0000000000",
			)
		}
		wg.Wait()
		newBucket, _, err := LoadStreamConfigForTest(env.server)
		require.NoError(t, err)

		oldBucket, err := providers.OpenBucket(t.Context(), oldBucketURI)
		require.NoError(t, err)
		defer func() {
			_ = oldBucket.Close()
		}()

		// old bucket has interrupted objects
		blobtestutil.TestFullPathsMatchExactly(t, oldBucket, expectedObjs)
		blobtestutil.TestSchemaIDsMatchExactly(t, oldBucket, env.schema("").SchemaV1, []string{"rec-0", "rec-1"})

		// new bucket has new objects
		blobtestutil.TestFullPathsMatchExactly(t, newBucket, expectedObjs)
		blobtestutil.TestSchemaIDsMatchExactly(t, newBucket, env.schema("").SchemaV1, []string{"rec-0", "rec-1"})
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
				require.NoError(t, client.recvHandshake())
				id := fmt.Sprintf("rec-%d", i)
				metadata := makeMetadata(id, &ssh.RecordingMetadata{ProtocolVersion: 42})
				chunks, checksum := makeChunks(id, [][]byte{
					[]byte("chunk1"), []byte("chunk2"), []byte("chunk3"),
				})
				expectedManifest := &xrecording.ChunkManifest{
					Items: []*xrecording.ChunkMetadata{
						{Size: 18, Checksum: checksum.GetChunkMetadata().GetChecksum()},
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
				bucket, _, err := LoadStreamConfigForTest(env.server)
				require.NoError(t, err)
				blobtestutil.TestFullObjectMatches(t, bucket, env.schema(id),
					metadata,
					expectedManifest,
					[]byte("chunk1chunk2chunk3"),
					&xrecording.RecordingTrailer{EnvoyVersion: "Envoy v0.0.0+"},
				)
			})
		}
		wg.Wait()
		bucket, _, err := LoadStreamConfigForTest(env.server)
		require.NoError(t, err)
		blobtestutil.TestSchemaIDsMatchExactly(t, bucket, env.schema("").SchemaV1, expectedIDs)
	})

	t.Run("protocol failures", func(t *testing.T) {
		t.Run("metadata not sent before chunk/trailers", func(t *testing.T) {
			env := envF(t, 1)
			client := env.clients[0]
			require.NoError(t, client.recvHandshake())

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
					name: "chunk metadata before recording metadata",
					in: []*xrecording.RecordingData{
						{
							RecordingId: "checksum-first",
							Data: &xrecording.RecordingData_ChunkMetadata{
								ChunkMetadata: &xrecording.ChunkMetadata{
									Checksum: []byte("checksum"),
								},
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
			require.NoError(t, client.recvHandshake())

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
			require.NoError(t, client.recvHandshake())

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

		t.Run("trailer with unflushed chunks", func(t *testing.T) {
			env := envF(t, 1)
			client := env.clients[0]
			require.NoError(t, client.recvHandshake())

			tcs := []protocolTestcase{
				{
					name: "metadata handshake",
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
					name: "chunk without checksum, then trailer is rejected",
					in: []*xrecording.RecordingData{
						makeChunkOne("foo", []byte("unflushed-payload")),
						makeTrailer("foo", "Envoy v0.0.0+"),
					},
					out: []testcaseRecv{
						{
							msg: &xrecording.RecordingCheckpoint{
								RecordingId: "foo",
								Status:      errorStatus(ErrUnflushedChunks),
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
			require.NoError(t, client.recvHandshake())

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
