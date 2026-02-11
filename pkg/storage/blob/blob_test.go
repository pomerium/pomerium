package blob_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/thanos-io/objstore"
	"google.golang.org/protobuf/proto"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/storage/blob"
)

func TestBlobStore(t *testing.T) {
	t.Parallel()

	tcOpts := []struct {
		name           string
		installationID string
		opts           []blob.Option
	}{
		{
			name: "without installation ID",
			opts: []blob.Option{blob.WithInMemory()},
		},
		{
			name:           "with installation ID",
			installationID: "inst-1",
			opts:           []blob.Option{blob.WithIncludeInstallationID(), blob.WithInMemory()},
		},
	}

	for _, tc := range tcOpts {
		t.Run(tc.name, BlobConformanceTest(tc.installationID, tc.opts...))
	}
}

func BlobConformanceTest(installationID string, opts ...blob.Option) func(t *testing.T) {
	return func(t *testing.T) {
		t.Parallel()
		bucket := objstore.NewInMemBucket()
		cfg := &config.Config{Options: &config.Options{InstallationID: installationID}}
		store := blob.NewStore[session.Session](context.Background(), "test-prefix", opts...)
		store.OnConfigChange(t.Context(), cfg)
		t.Cleanup(store.Stop)

		t.Run("put and get round-trip", testPutAndGetRoundTrip(store, bucket))
		t.Run("get nonexistent key returns error", testGetNonexistentKey(store, bucket))
		t.Run("different keys are isolated", testDifferentKeysAreIsolated(store, bucket))
		t.Run("overwrite existing key", testOverwriteExistingKey(store, bucket))
		t.Run("empty contents and metadata", testEmptyContentsAndMetadata(store, bucket))
		t.Run("keys with path separators", testKeysWithPathSeparators(store, bucket))
	}
}

func testPutAndGetRoundTrip(store *blob.Store[session.Session, *session.Session], _ *objstore.InMemBucket) func(t *testing.T) {
	return func(t *testing.T) {
		t.Helper()
		ctx := context.Background()

		metadata := []byte(`{"version": 1}`)
		contents := []byte("hello world")

		err := store.Put(ctx, "rt-key", bytes.NewReader(metadata), bytes.NewReader(contents))
		require.NoError(t, err)

		gotContents, err := store.GetContents(ctx, "rt-key")
		require.NoError(t, err)
		assert.Equal(t, contents, gotContents)

		gotMetadata, err := store.GetMetadata(ctx, "rt-key")
		require.NoError(t, err)
		assert.Equal(t, metadata, gotMetadata)
	}
}

func testGetNonexistentKey(store *blob.Store[session.Session, *session.Session], _ *objstore.InMemBucket) func(t *testing.T) {
	return func(t *testing.T) {
		t.Helper()
		ctx := context.Background()

		_, err := store.GetContents(ctx, "does-not-exist")
		assert.Error(t, err)

		_, err = store.GetMetadata(ctx, "does-not-exist")
		assert.Error(t, err)
	}
}

func testDifferentKeysAreIsolated(store *blob.Store[session.Session, *session.Session], _ *objstore.InMemBucket) func(t *testing.T) {
	return func(t *testing.T) {
		t.Helper()
		ctx := context.Background()

		require.NoError(t, store.Put(ctx, "iso-a", bytes.NewReader([]byte("meta-a")), bytes.NewReader([]byte("content-a"))))
		require.NoError(t, store.Put(ctx, "iso-b", bytes.NewReader([]byte("meta-b")), bytes.NewReader([]byte("content-b"))))

		gotA, err := store.GetContents(ctx, "iso-a")
		require.NoError(t, err)
		assert.Equal(t, []byte("content-a"), gotA)

		gotB, err := store.GetContents(ctx, "iso-b")
		require.NoError(t, err)
		assert.Equal(t, []byte("content-b"), gotB)
	}
}

func testOverwriteExistingKey(store *blob.Store[session.Session, *session.Session], _ *objstore.InMemBucket) func(t *testing.T) {
	return func(t *testing.T) {
		t.Helper()
		ctx := context.Background()

		require.NoError(t, store.Put(ctx, "ow-key", bytes.NewReader([]byte("meta-v1")), bytes.NewReader([]byte("v1"))))
		require.NoError(t, store.Put(ctx, "ow-key", bytes.NewReader([]byte("meta-v2")), bytes.NewReader([]byte("v2"))))

		got, err := store.GetContents(ctx, "ow-key")
		require.NoError(t, err)
		assert.Equal(t, []byte("v2"), got)

		gotMeta, err := store.GetMetadata(ctx, "ow-key")
		require.NoError(t, err)
		assert.Equal(t, []byte("meta-v2"), gotMeta)
	}
}

func testEmptyContentsAndMetadata(store *blob.Store[session.Session, *session.Session], _ *objstore.InMemBucket) func(t *testing.T) {
	return func(t *testing.T) {
		t.Helper()
		ctx := context.Background()

		require.NoError(t, store.Put(ctx, "empty-key", bytes.NewReader(nil), bytes.NewReader(nil)))

		got, err := store.GetContents(ctx, "empty-key")
		require.NoError(t, err)
		assert.Empty(t, got)

		gotMeta, err := store.GetMetadata(ctx, "empty-key")
		require.NoError(t, err)
		assert.Empty(t, gotMeta)
	}
}

func testKeysWithPathSeparators(store *blob.Store[session.Session, *session.Session], _ *objstore.InMemBucket) func(t *testing.T) {
	return func(t *testing.T) {
		t.Helper()
		ctx := context.Background()

		require.NoError(t, store.Put(ctx, "a/b/c", bytes.NewReader([]byte("meta")), bytes.NewReader([]byte("nested"))))

		got, err := store.GetContents(ctx, "a/b/c")
		require.NoError(t, err)
		assert.Equal(t, []byte("nested"), got)
	}
}

func mustMarshalSession(t *testing.T, s *session.Session) []byte {
	t.Helper()
	data, err := proto.Marshal(s)
	require.NoError(t, err)
	return data
}

func TestBlobStore_InstallationIDChangeIsolatesData(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{Options: &config.Options{InstallationID: "inst-1"}}
	store := blob.NewStore[session.Session](context.Background(), "test-prefix", blob.WithIncludeInstallationID(), blob.WithInMemory())
	store.OnConfigChange(t.Context(), cfg)
	t.Cleanup(store.Stop)

	ctx := context.Background()

	require.NoError(t, store.Put(ctx, "change-key", bytes.NewReader([]byte("meta-1")), bytes.NewReader([]byte("data-1"))))

	store.OnConfigChange(ctx, &config.Config{Options: &config.Options{InstallationID: "inst-2"}})

	_, err := store.GetContents(ctx, "change-key")
	assert.Error(t, err, "data from old installation ID should not be accessible")

	require.NoError(t, store.Put(ctx, "change-key", bytes.NewReader([]byte("meta-2")), bytes.NewReader([]byte("data-2"))))

	got, err := store.GetContents(ctx, "change-key")
	require.NoError(t, err)
	assert.Equal(t, []byte("data-2"), got)
}
