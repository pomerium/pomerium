package recording_test

import (
	"context"
	"crypto/md5"
	"errors"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gblob "gocloud.dev/blob"
	_ "gocloud.dev/blob/fileblob"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/pomerium/envoy-custom/api/x/recording"
	"github.com/pomerium/pomerium/config"
	rec "github.com/pomerium/pomerium/internal/recording"
	"github.com/pomerium/pomerium/internal/testutil"
	"github.com/pomerium/pomerium/pkg/protoutil"
	"github.com/pomerium/pomerium/pkg/storage/blob"
)

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

func newTestClient(t *testing.T, cfg *config.Config) recording.RecordingServiceClient {
	t.Helper()
	srv := rec.NewRecordingServer(t.Context(), cfg)
	cc := testutil.NewGRPCServer(t, func(s *grpc.Server) {
		recording.RegisterRecordingServiceServer(s, srv)
	})
	return recording.NewRecordingServiceClient(cc)
}

func sendMetadata(t *testing.T, stream recording.RecordingService_RecordClient, id string) *recording.RecordingSession {
	t.Helper()
	err := stream.Send(&recording.RecordingData{
		Data: &recording.RecordingData_Metadata{
			Metadata: &recording.RecordingMetadata{
				Id:            id,
				RecordingType: recording.RecordingFormat_RecordingFormatSSH,
				Metadata:      protoutil.NewAnyBytes([]byte("test")),
			},
		},
	})
	require.NoError(t, err)
	session, err := stream.Recv()
	require.NoError(t, err)
	return session
}

func TestRecordingServer(t *testing.T) {
	bucketProviders := []struct {
		name string
		uri  string
	}{
		{"fileblob", "file://" + t.TempDir()},
	}

	for _, tc := range bucketProviders {
		t.Run(tc.name, func(t *testing.T) {
			bk, err := gblob.OpenBucket(t.Context(), tc.uri)
			require.NoError(t, err)
			t.Cleanup(func() { _ = bk.Close() })
			testRecordingServerConformance(t, tc.uri, bk)
		})
	}
}

func testRecordingServerConformance(t *testing.T, bucketURI string, bk *gblob.Bucket) {
	t.Helper()

	t.Run("should upload successfully", func(t *testing.T) {
		cfg := defaultTestConfig(bucketURI)
		client := newTestClient(t, cfg)

		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()

		stream, err := client.Record(ctx)
		require.NoError(t, err)

		session := sendMetadata(t, stream, "upload")
		assert.Empty(t, session.GetManifest().GetItems())

		chunks := [][]byte{[]byte("foo"), []byte("bar"), []byte("baz")}
		var allData []byte
		for _, chunk := range chunks {
			allData = append(allData, chunk...)
			err = stream.Send(&recording.RecordingData{
				Data: &recording.RecordingData_Chunk{Chunk: chunk},
			})
			require.NoError(t, err)
		}

		checksum := md5.Sum(allData)
		err = stream.Send(&recording.RecordingData{
			Data: &recording.RecordingData_Checksum{Checksum: checksum[:]},
		})
		require.NoError(t, err)

		ack, err := stream.Recv()
		require.NoError(t, err)
		require.Len(t, ack.GetManifest().GetItems(), 1)
		assert.Equal(t, uint32(len(allData)), ack.GetManifest().GetItems()[0].GetSize())
		assert.Equal(t, checksum[:], ack.GetManifest().GetItems()[0].GetChecksum())

		err = stream.Send(&recording.RecordingData{
			Data: &recording.RecordingData_Sig{Sig: &recording.RecordingSignature{}},
		})
		require.NoError(t, err)

		err = stream.CloseSend()
		require.NoError(t, err)

		// Drain the stream so the server finishes writing before we read blobs.
		for {
			_, err := stream.Recv()
			if errors.Is(err, io.EOF) {
				break
			}
		}

		// Verify chunk data in blob store.
		chunkData, err := bk.ReadAll(ctx, "test/ssh/upload/0000000000")
		require.NoError(t, err)
		blobChecksum := md5.Sum(chunkData)
		assert.Equal(t, checksum, blobChecksum)
		assert.Equal(t, allData, chunkData)

		// Verify metadata proto.
		mdProtoData, err := bk.ReadAll(ctx, "test/ssh/upload.proto")
		assert.NoError(t, err)
		var mdProto recording.RecordingMetadata
		require.NoError(t, proto.Unmarshal(mdProtoData, &mdProto))
		assert.Equal(t, "upload", mdProto.GetId())
		assert.Equal(t, recording.RecordingFormat_RecordingFormatSSH, mdProto.GetRecordingType())

		// Verify metadata JSON.
		mdJSONData, err := bk.ReadAll(ctx, "test/ssh/upload.json")
		require.NoError(t, err)
		var mdJSON recording.RecordingMetadata
		require.NoError(t, protojson.Unmarshal(mdJSONData, &mdJSON))
		assert.Equal(t, "upload", mdJSON.GetId())
		assert.Equal(t, recording.RecordingFormat_RecordingFormatSSH, mdJSON.GetRecordingType())

		// Verify manifest.
		manifestData, err := bk.ReadAll(ctx, "test/ssh/upload/manifest")
		require.NoError(t, err)
		var manifest recording.ChunkManifest
		require.NoError(t, proto.Unmarshal(manifestData, &manifest))
		require.Len(t, manifest.GetItems(), 1)
		assert.Equal(t, uint32(len(allData)), manifest.GetItems()[0].GetSize())

		// Verify signature exists.
		sigExists, err := bk.Exists(ctx, "test/ssh/upload.sig")
		require.NoError(t, err)
		assert.True(t, sigExists)
	})

	t.Run("should resume from chunk manifest", func(t *testing.T) {
		cfg := defaultTestConfig(bucketURI)
		client := newTestClient(t, cfg)

		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()

		// First stream: upload one chunk.
		stream1, err := client.Record(ctx)
		require.NoError(t, err)
		_ = sendMetadata(t, stream1, "resume")

		chunk1 := []byte("aaaaaaa")
		err = stream1.Send(&recording.RecordingData{
			Data: &recording.RecordingData_Chunk{Chunk: chunk1},
		})
		require.NoError(t, err)

		checksum1 := md5.Sum(chunk1)
		err = stream1.Send(&recording.RecordingData{
			Data: &recording.RecordingData_Checksum{Checksum: checksum1[:]},
		})
		require.NoError(t, err)

		_, err = stream1.Recv()
		require.NoError(t, err)

		err = stream1.CloseSend()
		require.NoError(t, err)

		// Second stream: same ID, manifest should reflect the first chunk.
		stream2, err := client.Record(ctx)
		require.NoError(t, err)
		session := sendMetadata(t, stream2, "resume")

		items := session.GetManifest().GetItems()
		require.Len(t, items, 1)
		assert.Equal(t, uint32(len(chunk1)), items[0].GetSize())

		// Append a second chunk after resuming.
		chunk2 := []byte("bbbbbbb")
		err = stream2.Send(&recording.RecordingData{
			Data: &recording.RecordingData_Chunk{Chunk: chunk2},
		})
		require.NoError(t, err)

		checksum2 := md5.Sum(chunk2)
		err = stream2.Send(&recording.RecordingData{
			Data: &recording.RecordingData_Checksum{Checksum: checksum2[:]},
		})
		require.NoError(t, err)

		ack, err := stream2.Recv()
		require.NoError(t, err)
		require.Len(t, ack.GetManifest().GetItems(), 2)
		assert.Equal(t, uint32(len(chunk1)), ack.GetManifest().GetItems()[0].GetSize())
		assert.Equal(t, uint32(len(chunk2)), ack.GetManifest().GetItems()[1].GetSize())

		err = stream2.CloseSend()
		require.NoError(t, err)

		// Verify both chunks in blob store.
		chunk1Data, err := bk.ReadAll(ctx, "test/ssh/resume/0000000000")
		require.NoError(t, err)
		assert.Equal(t, chunk1, chunk1Data)

		chunk2Data, err := bk.ReadAll(ctx, "test/ssh/resume/0000000001")
		require.NoError(t, err)
		assert.Equal(t, chunk2, chunk2Data)

		// Recording was not finalized, so sig and manifest should not exist.
		sigExists, err := bk.Exists(ctx, "test/ssh/resume.sig")
		require.NoError(t, err)
		assert.False(t, sigExists, "signature should not exist before finalization")

		manifestExists, err := bk.Exists(ctx, "test/ssh/resume/manifest")
		require.NoError(t, err)
		assert.False(t, manifestExists, "manifest should not exist before finalization")
	})

	t.Run("multi-chunk upload", func(t *testing.T) {
		cfg := defaultTestConfig(bucketURI)
		client := newTestClient(t, cfg)

		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()

		stream, err := client.Record(ctx)
		require.NoError(t, err)
		_ = sendMetadata(t, stream, "multi")

		batches := [][]byte{
			[]byte("foo"),
			[]byte("bar"),
			[]byte("baz"),
		}

		for i, data := range batches {
			err = stream.Send(&recording.RecordingData{
				Data: &recording.RecordingData_Chunk{Chunk: data},
			})
			require.NoError(t, err)

			checksum := md5.Sum(data)
			err = stream.Send(&recording.RecordingData{
				Data: &recording.RecordingData_Checksum{Checksum: checksum[:]},
			})
			require.NoError(t, err)

			ack, err := stream.Recv()
			require.NoError(t, err)
			require.Len(t, ack.GetManifest().GetItems(), i+1,
				"manifest should have %d chunk(s) after batch %d", i+1, i+1)
		}

		// Finalize and drain.
		err = stream.Send(&recording.RecordingData{
			Data: &recording.RecordingData_Sig{Sig: &recording.RecordingSignature{}},
		})
		require.NoError(t, err)

		err = stream.CloseSend()
		require.NoError(t, err)

		for {
			_, err := stream.Recv()
			if errors.Is(err, io.EOF) {
				break
			}
		}

		// Verify each chunk in blob store.
		for i, data := range batches {
			key := fmt.Sprintf("test/ssh/multi/%010d", i)
			chunkData, err := bk.ReadAll(ctx, key)
			require.NoError(t, err, "chunk %d", i)
			assert.Equal(t, data, chunkData, "chunk %d data mismatch", i)

			blobChecksum := md5.Sum(chunkData)
			expectedChecksum := md5.Sum(data)
			assert.Equal(t, expectedChecksum, blobChecksum, "chunk %d checksum mismatch", i)
		}

		// Verify manifest has all chunks.
		manifestData, err := bk.ReadAll(ctx, "test/ssh/multi/manifest")
		require.NoError(t, err)
		var manifest recording.ChunkManifest
		require.NoError(t, proto.Unmarshal(manifestData, &manifest))
		require.Len(t, manifest.GetItems(), len(batches))
		for i, data := range batches {
			assert.Equal(t, uint32(len(data)), manifest.GetItems()[i].GetSize(),
				"manifest item %d size", i)
		}
	})
}

func newTestServerAndClient(t *testing.T, cfg *config.Config) (rec.Server, recording.RecordingServiceClient) {
	t.Helper()
	srv := rec.NewRecordingServer(t.Context(), cfg)
	cc := testutil.NewGRPCServer(t, func(s *grpc.Server) {
		recording.RegisterRecordingServiceServer(s, srv)
	})
	return srv, recording.NewRecordingServiceClient(cc)
}

func TestServerOnConfigChange(t *testing.T) {
	t.Run("existing client streams get an error when config reloads meaningfully", func(t *testing.T) {
		bucketA := t.TempDir()
		bucketB := t.TempDir()
		cfg := defaultTestConfig("file://" + bucketA)
		srv, client := newTestServerAndClient(t, cfg)

		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()

		// Establish stream — ChunkWriter now holds a reference to bucket A.
		stream, err := client.Record(ctx)
		require.NoError(t, err)
		_ = sendMetadata(t, stream, "in-flight")

		// Switch bucket URI — closes bucket A.
		newCfg := defaultTestConfig("file://" + bucketB)
		srv.OnConfigChange(t.Context(), newCfg)

		// Send a chunk + checksum on the existing stream.
		chunk := []byte("should-fail")
		_ = stream.Send(&recording.RecordingData{
			Data: &recording.RecordingData_Chunk{Chunk: chunk},
		})
		checksum := md5.Sum(chunk)
		_ = stream.Send(&recording.RecordingData{
			Data: &recording.RecordingData_Checksum{Checksum: checksum[:]},
		})

		// The write goroutine's WriteChunk hits a closed bucket → codes.Internal.
		_, err = stream.Recv()
		require.Error(t, err)

		assert.Equal(t, codes.Internal, status.Code(err))
	})

	t.Run("bucket URI change uses new bucket", func(t *testing.T) {
		bucketA := t.TempDir()
		bucketB := t.TempDir()
		cfg := defaultTestConfig("file://" + bucketA)
		srv, client := newTestServerAndClient(t, cfg)

		// Switch to bucket B.
		newCfg := defaultTestConfig("file://" + bucketB)
		srv.OnConfigChange(t.Context(), newCfg)

		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()

		stream, err := client.Record(ctx)
		require.NoError(t, err)
		_ = sendMetadata(t, stream, "switched")

		chunk := []byte("data-in-bucket-b")
		err = stream.Send(&recording.RecordingData{
			Data: &recording.RecordingData_Chunk{Chunk: chunk},
		})
		require.NoError(t, err)

		checksum := md5.Sum(chunk)
		err = stream.Send(&recording.RecordingData{
			Data: &recording.RecordingData_Checksum{Checksum: checksum[:]},
		})
		require.NoError(t, err)

		_, err = stream.Recv()
		require.NoError(t, err)

		err = stream.Send(&recording.RecordingData{
			Data: &recording.RecordingData_Sig{Sig: &recording.RecordingSignature{}},
		})
		require.NoError(t, err)

		err = stream.CloseSend()
		require.NoError(t, err)
		for {
			_, err := stream.Recv()
			if errors.Is(err, io.EOF) {
				break
			}
		}

		// Verify data landed in bucket B.
		bkB, err := gblob.OpenBucket(ctx, "file://"+bucketB)
		require.NoError(t, err)
		t.Cleanup(func() { _ = bkB.Close() })

		chunkData, err := bkB.ReadAll(ctx, "test/ssh/switched/0000000000")
		require.NoError(t, err)
		assert.Equal(t, chunk, chunkData)

		// Verify data did NOT land in bucket A.
		bkA, err := gblob.OpenBucket(ctx, "file://"+bucketA)
		require.NoError(t, err)
		t.Cleanup(func() { _ = bkA.Close() })

		exists, err := bkA.Exists(ctx, "test/ssh/switched/0000000000")
		require.NoError(t, err)
		assert.False(t, exists, "data should not exist in old bucket")
	})

	t.Run("invalid", func(t *testing.T) {
		bucketURI := "file://" + t.TempDir()
		cfg := defaultTestConfig(bucketURI)
		srv, client := newTestServerAndClient(t, cfg)

		// Switch to invalid bucket.
		badCfg := defaultTestConfig(bucketURI)
		badCfg.Options.BlobStorage.BucketURI = "invalid://nope"
		srv.OnConfigChange(t.Context(), badCfg)

		stream, err := client.Record(t.Context())
		require.NoError(t, err)
		_ = stream.Send(&recording.RecordingData{
			Data: &recording.RecordingData_Metadata{
				Metadata: &recording.RecordingMetadata{
					Id:            "bad-bucket",
					RecordingType: recording.RecordingFormat_RecordingFormatSSH,
					Metadata:      protoutil.NewAnyBytes([]byte("test")),
				},
			},
		})
		_, err = stream.Recv()
		require.Error(t, err)
		assert.Equal(t, codes.Unavailable, status.Code(err))
	})

	t.Run("invalid then valid", func(t *testing.T) {
		bucketURI := "file://" + t.TempDir()
		cfg := defaultTestConfig(bucketURI)
		srv, client := newTestServerAndClient(t, cfg)

		// Break with invalid URI.
		badCfg := defaultTestConfig(bucketURI)
		badCfg.Options.BlobStorage.BucketURI = "invalid://nope"
		srv.OnConfigChange(t.Context(), badCfg)

		// Verify it's broken.
		stream, err := client.Record(t.Context())
		require.NoError(t, err)
		_ = stream.Send(&recording.RecordingData{
			Data: &recording.RecordingData_Metadata{
				Metadata: &recording.RecordingMetadata{
					Id:            "broken",
					RecordingType: recording.RecordingFormat_RecordingFormatSSH,
					Metadata:      protoutil.NewAnyBytes([]byte("test")),
				},
			},
		})
		_, err = stream.Recv()
		require.Error(t, err)
		assert.Equal(t, codes.Unavailable, status.Code(err))

		// Recover with valid config.
		srv.OnConfigChange(t.Context(), cfg)

		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()

		stream2, err := client.Record(ctx)
		require.NoError(t, err)
		session := sendMetadata(t, stream2, "recovered")
		assert.NotNil(t, session.Manifest)

		chunk := []byte("after-recovery")
		err = stream2.Send(&recording.RecordingData{
			Data: &recording.RecordingData_Chunk{Chunk: chunk},
		})
		require.NoError(t, err)

		checksum := md5.Sum(chunk)
		err = stream2.Send(&recording.RecordingData{
			Data: &recording.RecordingData_Checksum{Checksum: checksum[:]},
		})
		require.NoError(t, err)

		ack, err := stream2.Recv()
		require.NoError(t, err)
		require.Len(t, ack.GetManifest().GetItems(), 1)

		err = stream2.CloseSend()
		require.NoError(t, err)
	})

	t.Run("same bucket URI", func(t *testing.T) {
		bucketURI := "file://" + t.TempDir()
		cfg := defaultTestConfig(bucketURI)
		srv, client := newTestServerAndClient(t, cfg)

		// Re-apply same config.
		srv.OnConfigChange(t.Context(), cfg)

		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()

		stream, err := client.Record(ctx)
		require.NoError(t, err)
		session := sendMetadata(t, stream, "same-uri")
		assert.NotNil(t, session.Manifest)

		chunk := []byte("still-works")
		err = stream.Send(&recording.RecordingData{
			Data: &recording.RecordingData_Chunk{Chunk: chunk},
		})
		require.NoError(t, err)

		checksum := md5.Sum(chunk)
		err = stream.Send(&recording.RecordingData{
			Data: &recording.RecordingData_Checksum{Checksum: checksum[:]},
		})
		require.NoError(t, err)

		ack, err := stream.Recv()
		require.NoError(t, err)
		require.Len(t, ack.GetManifest().GetItems(), 1)

		err = stream.CloseSend()
		require.NoError(t, err)
	})
}
