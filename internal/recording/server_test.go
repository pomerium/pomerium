package recording_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gblob "gocloud.dev/blob"
	_ "gocloud.dev/blob/fileblob"

	"github.com/pomerium/envoy-custom/api/x/recording"
	"github.com/pomerium/pomerium/config"
	rec "github.com/pomerium/pomerium/internal/recording"
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
			GlobalOptions: config.GlobalOptions{
				SessionRecordingIpcMode: new("grpc"),
			},
		},
	}
}

func sendMetadata(t *testing.T, stream recording.RecordingService_RecordClient, id string) *recording.RecordingCheckpoint {
	t.Helper()
	err := stream.Send(&recording.RecordingData{
		RecordingId: id,
		Data: &recording.RecordingData_Metadata{
			Metadata: &recording.RecordingMetadata{
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

func TestServerOnConfigChange(t *testing.T) {
	t.Run("bucket URI change swaps the bucket", func(t *testing.T) {
		dirA := t.TempDir()
		dirB := t.TempDir()
		srv := rec.NewRecordingServer(t.Context(), defaultTestConfig("file://"+dirA))

		before, prefix, err := rec.LoadStreamConfigForTest(srv)
		require.NoError(t, err)
		require.NotNil(t, before)
		assert.Equal(t, "test", prefix)

		srv.OnConfigChange(t.Context(), defaultTestConfig("file://"+dirB))

		after, _, err := rec.LoadStreamConfigForTest(srv)
		require.NoError(t, err)
		require.NotNil(t, after)
		assert.NotSame(t, before, after, "bucket pointer should be replaced when URI changes")

		// Writes via the server's current bucket must land in B, not A.
		require.NoError(t, after.WriteAll(t.Context(), "probe", []byte("hello"), nil))

		bkB, err := gblob.OpenBucket(t.Context(), "file://"+dirB)
		require.NoError(t, err)
		t.Cleanup(func() { _ = bkB.Close() })
		got, err := bkB.ReadAll(t.Context(), "probe")
		require.NoError(t, err)
		assert.Equal(t, []byte("hello"), got)

		bkA, err := gblob.OpenBucket(t.Context(), "file://"+dirA)
		require.NoError(t, err)
		t.Cleanup(func() { _ = bkA.Close() })
		exists, err := bkA.Exists(t.Context(), "probe")
		require.NoError(t, err)
		assert.False(t, exists, "old bucket must not receive writes after swap")
	})

	t.Run("same bucket URI is a no-op", func(t *testing.T) {
		cfg := defaultTestConfig("file://" + t.TempDir())
		srv := rec.NewRecordingServer(t.Context(), cfg)

		before, _, err := rec.LoadStreamConfigForTest(srv)
		require.NoError(t, err)
		require.NotNil(t, before)

		srv.OnConfigChange(t.Context(), cfg)

		after, _, err := rec.LoadStreamConfigForTest(srv)
		require.NoError(t, err)
		assert.Same(t, before, after, "bucket pointer should not change when URI is unchanged")
	})

	t.Run("invalid bucket URI surfaces an error", func(t *testing.T) {
		srv := rec.NewRecordingServer(t.Context(), defaultTestConfig("invalid://nope"))

		bucket, _, err := rec.LoadStreamConfigForTest(srv)
		require.Error(t, err, "bucketErr should be populated when the URI cannot be opened")
		assert.Nil(t, bucket)
	})

	t.Run("invalid URI can be recovered via a follow-up valid config", func(t *testing.T) {
		srv := rec.NewRecordingServer(t.Context(), defaultTestConfig("invalid://nope"))

		_, _, err := rec.LoadStreamConfigForTest(srv)
		require.Error(t, err)

		srv.OnConfigChange(t.Context(), defaultTestConfig("file://"+t.TempDir()))

		bucket, _, err := rec.LoadStreamConfigForTest(srv)
		require.NoError(t, err, "bucketErr should clear once a valid URI is applied")
		require.NotNil(t, bucket)
	})

	t.Run("valid then invalid clears the working bucket", func(t *testing.T) {
		srv := rec.NewRecordingServer(t.Context(), defaultTestConfig("file://"+t.TempDir()))

		before, _, err := rec.LoadStreamConfigForTest(srv)
		require.NoError(t, err)
		require.NotNil(t, before)

		srv.OnConfigChange(t.Context(), defaultTestConfig("invalid://nope"))

		after, _, err := rec.LoadStreamConfigForTest(srv)
		require.Error(t, err)
		assert.Nil(t, after, "bucket should be cleared when the new URI fails to open")
	})

	t.Run("nil BlobStorage config does not panic", func(t *testing.T) {
		cfgWithoutBucket := defaultTestConfig("")
		cfgWithoutBucket.Options.BlobStorage = nil
		cfgWithBucket := defaultTestConfig("file://" + t.TempDir())

		assert.NotPanics(t, func() {
			srv := rec.NewRecordingServer(t.Context(), cfgWithoutBucket)
			srv.OnConfigChange(t.Context(), cfgWithoutBucket)
		})

		assert.NotPanics(t, func() {
			srv := rec.NewRecordingServer(t.Context(), cfgWithBucket)
			srv.OnConfigChange(t.Context(), cfgWithoutBucket)
		})

		assert.NotPanics(t, func() {
			srv := rec.NewRecordingServer(t.Context(), cfgWithoutBucket)
			srv.OnConfigChange(t.Context(), cfgWithBucket)
			bucket, _, err := rec.LoadStreamConfigForTest(srv)
			require.NoError(t, err)
			require.NotNil(t, bucket)
		})
	})
}
