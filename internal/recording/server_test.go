package recording

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gblob "gocloud.dev/blob"
	_ "gocloud.dev/blob/fileblob"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/wrapperspb"

	xrecording "github.com/pomerium/envoy-custom/api/x/recording"
	"github.com/pomerium/envoy-custom/api/x/recording/formats/ssh"
	xssh "github.com/pomerium/envoy-custom/api/x/recording/formats/ssh"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/pkg/storage/blob"
)

const noTmpDir = "?no_tmp_dir=true"

func TestServerOnConfigChangePipes(t *testing.T) {
	tempDir := t.TempDir()
	pipes, err := SetupRecordingPipes(&xssh.Config{
		UploadConfig: &xssh.UploadConfig{
			Concurrency: &wrapperspb.UInt32Value{
				Value: uint32(1),
			},
			IpcMode: &xssh.UploadConfig_PipeIpc_{},
		},
	})
	require.NoError(t, err)
	require.Len(t, pipes, 1)

	cfg := &config.Config{
		Options: &config.Options{
			BlobStorage: &blob.StorageConfig{
				BucketURI:     "file://" + tempDir + noTmpDir,
				ManagedPrefix: "test",
			},
		},
	}
	srv, err := NewRecordingServer(t.Context(), cfg, TransportOptions{
		Pipes:       pipes,
		Concurrency: uint32(len(pipes)),
	})

	require.NoError(t, err)
	errC := make(chan error, 1)
	go func() {
		errC <- srv.Serve(t.Context())
	}()

	select {
	case err := <-errC:
		assert.Fail(t, "serving did not start running properly", err.Error())
	default:
	}

	pipes2, err := SetupRecordingPipes(&xssh.Config{
		UploadConfig: &xssh.UploadConfig{
			Concurrency: &wrapperspb.UInt32Value{
				Value: uint32(1),
			},
			IpcMode: &xssh.UploadConfig_PipeIpc_{},
		},
	})

	require.Len(t, pipes2, 1)
	opts2 := TransportOptions{
		Pipes:       pipes2,
		Concurrency: uint32(len(pipes2)),
	}
	require.NoError(t, err)
	srv.OnTransportChange(t.Context(), opts2)

	select {
	case err := <-errC:
		if err != nil {
			assert.Fail(t, "config change should not cause serve to exit", err.Error())
		} else {
			assert.Fail(t, "config change should not cause serve to exit")
		}
	default:
	}

	client := newPipeClientTransportProtocol(
		t,
		pipes2[0].uploadWrite,
		pipes2[0].checkpointRead,
	)
	fooMetadata := makeMetadata("foo", &ssh.RecordingMetadata{ProtocolVersion: uint32(42)})
	require.NoError(t, client.Send(t.Context(), fooMetadata))

	checkpoint, err := client.Recv(t.Context())
	require.NoError(t, err)
	assert.Empty(t, cmp.Diff(&xrecording.RecordingCheckpoint{
		RecordingId: "foo",
		Manifest:    &xrecording.ChunkManifest{},
	}, checkpoint, protocmp.Transform()))

	require.NoError(t, srv.Shutdown(t.Context()), "shutdown failed")
	assert.NoError(t, <-errC, "expected pipe IPC to shutdown gracefully")
}

func TestServerOnConfigChangeBlobConfig(t *testing.T) {
	t.Run("bucket URI change swaps the bucket", func(t *testing.T) {
		dirA := t.TempDir()
		dirB := t.TempDir()
		srv := defaultPipeRecordingServer(t, defaultTestConfig("file://"+dirA+noTmpDir))

		before, prefix, err := LoadStreamConfigForTest(srv)
		require.NoError(t, err)
		require.NotNil(t, before)
		assert.Equal(t, "test", prefix)

		srv.OnConfigChange(t.Context(), defaultTestConfig("file://"+dirB+noTmpDir))

		after, _, err := LoadStreamConfigForTest(srv)
		require.NoError(t, err)
		require.NotNil(t, after)
		assert.NotSame(t, before, after, "bucket pointer should be replaced when URI changes")

		// Writes via the server's current bucket must land in B, not A.
		require.NoError(t, after.WriteAll(t.Context(), "probe", []byte("hello"), nil))

		bkB, err := gblob.OpenBucket(t.Context(), "file://"+dirB+noTmpDir)
		require.NoError(t, err)
		t.Cleanup(func() { _ = bkB.Close() })
		got, err := bkB.ReadAll(t.Context(), "probe")
		require.NoError(t, err)
		assert.Equal(t, []byte("hello"), got)

		bkA, err := gblob.OpenBucket(t.Context(), "file://"+dirA+noTmpDir)
		require.NoError(t, err)
		t.Cleanup(func() { _ = bkA.Close() })
		exists, err := bkA.Exists(t.Context(), "probe")
		require.NoError(t, err)
		assert.False(t, exists, "old bucket must not receive writes after swap")
	})

	t.Run("same bucket URI is a no-op", func(t *testing.T) {
		cfg := defaultTestConfig("mem://" + uuid.New().String())
		srv := defaultPipeRecordingServer(t, cfg)

		before, _, err := LoadStreamConfigForTest(srv)
		require.NoError(t, err)
		require.NotNil(t, before)

		srv.OnConfigChange(t.Context(), cfg)

		after, _, err := LoadStreamConfigForTest(srv)
		require.NoError(t, err)
		assert.Same(t, before, after, "bucket pointer should not change when URI is unchanged")
	})

	t.Run("invalid bucket URI surfaces an error", func(t *testing.T) {
		srv := defaultPipeRecordingServer(t, defaultTestConfig("invalid://nope"))
		bucket, _, err := LoadStreamConfigForTest(srv)
		require.Error(t, err, "bucketErr should be populated when the URI cannot be opened")
		assert.Nil(t, bucket)
	})

	t.Run("invalid URI can be recovered via a follow-up valid config", func(t *testing.T) {
		srv := defaultPipeRecordingServer(t, defaultTestConfig("invalid://nope"))

		_, _, err := LoadStreamConfigForTest(srv)
		require.Error(t, err)

		srv.OnConfigChange(t.Context(), defaultTestConfig("mem://"+uuid.New().String()))

		bucket, _, err := LoadStreamConfigForTest(srv)
		require.NoError(t, err, "bucketErr should clear once a valid URI is applied")
		require.NotNil(t, bucket)
	})

	t.Run("valid then invalid clears the working bucket", func(t *testing.T) {
		srv := defaultPipeRecordingServer(t, defaultTestConfig("mem://"+uuid.New().String()))

		before, _, err := LoadStreamConfigForTest(srv)
		require.NoError(t, err)
		require.NotNil(t, before)

		srv.OnConfigChange(t.Context(), defaultTestConfig("invalid://nope"))

		after, _, err := LoadStreamConfigForTest(srv)
		require.Error(t, err)
		assert.Nil(t, after, "bucket should be cleared when the new URI fails to open")
	})

	t.Run("nil BlobStorage config does not panic", func(t *testing.T) {
		cfgWithoutBucket := defaultTestConfig("")
		cfgWithoutBucket.Options.BlobStorage = nil
		cfgWithBucket := defaultTestConfig("mem://" + uuid.New().String())

		assert.NotPanics(t, func() {
			srv := defaultPipeRecordingServer(t, cfgWithBucket)
			srv.OnConfigChange(t.Context(), cfgWithoutBucket)
		})

		assert.NotPanics(t, func() {
			srv := defaultPipeRecordingServer(t, cfgWithoutBucket)
			srv.OnConfigChange(t.Context(), cfgWithoutBucket)
		})

		assert.NotPanics(t, func() {
			srv := defaultPipeRecordingServer(t, cfgWithoutBucket)
			srv.OnConfigChange(t.Context(), cfgWithBucket)
			bucket, _, err := LoadStreamConfigForTest(srv)
			require.NoError(t, err)
			require.NotNil(t, bucket)
		})
	})
}
