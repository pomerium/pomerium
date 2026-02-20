package recording_test

import (
	"context"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/recording"
	"github.com/pomerium/pomerium/internal/testutil"
	recordingpb "github.com/pomerium/pomerium/pkg/grpc/recording"
	"github.com/pomerium/pomerium/pkg/storage/blob"
)

func defaultTestConfig() *config.Config {
	return &config.Config{
		Options: &config.Options{
			RecordingServerConfig: &config.RecordingServerConfig{
				MaxConcurrentStreams: 8,
				MaxChunkBatchNum:     3,
				MaxChunkSize:         64 << 10,
			},
		},
	}
}

func newTestClientWithConfig(t *testing.T, cfg *config.Config) recordingpb.RecordingServiceClient {
	t.Helper()
	srv := recording.NewRecordingServer(t.Context(), cfg, "test-prefix", blob.WithInMemory())
	cc := testutil.NewGRPCServer(t, func(s *grpc.Server) {
		recordingpb.RegisterRecordingServiceServer(s, srv)
	})
	return recordingpb.NewRecordingServiceClient(cc)
}

func sendMetadata(t *testing.T, stream recordingpb.RecordingService_RecordClient, id string) *recordingpb.RecordingSession {
	t.Helper()
	err := stream.Send(&recordingpb.RecordingData{
		Data: &recordingpb.RecordingData_Metadata{
			Metadata: &recordingpb.RecordingMetadata{Id: id},
		},
	})
	require.NoError(t, err)
	session, err := stream.Recv()
	require.NoError(t, err)
	return session
}

func TestRecordingServer(t *testing.T) {
	t.Run("resource exhausted on max streams", func(t *testing.T) {
		cfg := defaultTestConfig()
		cfg.Options.RecordingServerConfig.MaxConcurrentStreams = 1
		client := newTestClientWithConfig(t, cfg)

		stream1, err := client.Record(t.Context())
		require.NoError(t, err)
		_ = sendMetadata(t, stream1, "stream-1")

		stream2, err := client.Record(t.Context())
		require.NoError(t, err)

		_ = stream2.Send(&recordingpb.RecordingData{
			Data: &recordingpb.RecordingData_Metadata{
				Metadata: &recordingpb.RecordingMetadata{Id: "stream-2"},
			},
		})

		_, err = stream2.Recv()
		require.Error(t, err)
		assert.Equal(t, codes.ResourceExhausted, status.Code(err))
	})

	t.Run("aborted on too many chunks", func(t *testing.T) {
		cfg := defaultTestConfig()
		cfg.Options.RecordingServerConfig.MaxChunkBatchNum = 2
		client := newTestClientWithConfig(t, cfg)

		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()

		stream, err := client.Record(ctx)
		require.NoError(t, err)
		_ = sendMetadata(t, stream, "too-many-chunks")

		for i := range 3 {
			_ = stream.Send(&recordingpb.RecordingData{
				Data: &recordingpb.RecordingData_Chunk{Chunk: []byte{byte(i)}},
			})
		}

		_, err = stream.Recv()
		require.Error(t, err)
		assert.Equal(t, codes.Aborted, status.Code(err))
	})

	t.Run("should upload successfully", func(t *testing.T) {
		cfg := defaultTestConfig()
		cfg.Options.RecordingServerConfig.MaxChunkBatchNum = 3
		client := newTestClientWithConfig(t, cfg)

		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()

		stream, err := client.Record(ctx)
		require.NoError(t, err)

		session := sendMetadata(t, stream, "upload")
		assert.Empty(t, session.GetManifest().GetItems())
		assert.Equal(t, uint32(3), session.GetConfig().GetMaxChunkBatchNum())

		chunks := [][]byte{[]byte("foo"), []byte("bar"), []byte("baz")}
		var allData []byte
		for _, chunk := range chunks {
			allData = append(allData, chunk...)
			err = stream.Send(&recordingpb.RecordingData{
				Data: &recordingpb.RecordingData_Chunk{Chunk: chunk},
			})
			require.NoError(t, err)
		}

		checksum := sha256.Sum256(allData)
		err = stream.Send(&recordingpb.RecordingData{
			Data: &recordingpb.RecordingData_Checksum{Checksum: checksum[:]},
		})
		require.NoError(t, err)

		ack, err := stream.Recv()
		require.NoError(t, err)
		require.Len(t, ack.GetManifest().GetItems(), 1)
		assert.Equal(t, uint32(len(allData)), ack.GetManifest().GetItems()[0].GetSize())

		err = stream.CloseSend()
		require.NoError(t, err)
	})

	t.Run("should resume from chunk manifest", func(t *testing.T) {
		cfg := defaultTestConfig()
		cfg.Options.RecordingServerConfig.MaxChunkBatchNum = 1
		client := newTestClientWithConfig(t, cfg)

		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()

		// First stream: upload one chunk.
		stream1, err := client.Record(ctx)
		require.NoError(t, err)
		_ = sendMetadata(t, stream1, "resume")

		chunk1 := []byte("aaaaaaa")
		err = stream1.Send(&recordingpb.RecordingData{
			Data: &recordingpb.RecordingData_Chunk{Chunk: chunk1},
		})
		require.NoError(t, err)

		checksum1 := sha256.Sum256(chunk1)
		err = stream1.Send(&recordingpb.RecordingData{
			Data: &recordingpb.RecordingData_Checksum{Checksum: checksum1[:]},
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
		assert.Equal(t, checksum1[:], items[0].GetChecksum())

		err = stream2.CloseSend()
		require.NoError(t, err)
	})

	t.Run("multi-part upload", func(t *testing.T) {
		cfg := defaultTestConfig()
		cfg.Options.RecordingServerConfig.MaxChunkBatchNum = 2
		client := newTestClientWithConfig(t, cfg)

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
			err = stream.Send(&recordingpb.RecordingData{
				Data: &recordingpb.RecordingData_Chunk{Chunk: data},
			})
			require.NoError(t, err)

			checksum := sha256.Sum256(data)
			err = stream.Send(&recordingpb.RecordingData{
				Data: &recordingpb.RecordingData_Checksum{Checksum: checksum[:]},
			})
			require.NoError(t, err)

			ack, err := stream.Recv()
			require.NoError(t, err)
			require.Len(t, ack.GetManifest().GetItems(), i+1,
				"manifest should have %d chunk(s) after batch %d", i+1, i+1)
		}

		err = stream.CloseSend()
		require.NoError(t, err)
	})
}
