package blob_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/thanos-io/objstore"
	"google.golang.org/protobuf/proto"

	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/storage/blob"
)

// putWithContent is a test helper that writes metadata and a single content chunk.
func putWithContent(t *testing.T, store *blob.Store[session.Session, *session.Session], key string, metadata, contents []byte) {
	t.Helper()
	ctx := t.Context()
	cw, err := store.Start(ctx, key, bytes.NewReader(metadata))
	require.NoError(t, err)
	if len(contents) > 0 {
		checksum := sha256.Sum256(contents)
		require.NoError(t, cw.WriteChunk(ctx, contents, checksum))
	}
	require.NoError(t, cw.Finalize(ctx))
}

// getContents is a test helper that reads all chunks for a key.
func getContents(t *testing.T, store *blob.Store[session.Session, *session.Session], key string) []byte {
	t.Helper()
	ctx := t.Context()
	cr, err := store.ChunkReader(ctx, key)
	require.NoError(t, err)
	data, err := cr.GetAll(ctx)
	require.NoError(t, err)
	return data
}

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
		store := blob.NewStore[session.Session](context.Background(), "test-prefix", opts...)
		store.OnConfigChange(t.Context(), bucket)
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

		metadata := []byte(`{"version": 1}`)
		contents := []byte("hello world")

		putWithContent(t, store, "rt-key", metadata, contents)

		gotContents := getContents(t, store, "rt-key")
		assert.Equal(t, contents, gotContents)

		gotMetadata, err := store.GetMetadata(t.Context(), "rt-key")
		require.NoError(t, err)
		assert.Equal(t, metadata, gotMetadata)
	}
}

func testGetNonexistentKey(store *blob.Store[session.Session, *session.Session], _ *objstore.InMemBucket) func(t *testing.T) {
	return func(t *testing.T) {
		t.Helper()
		ctx := context.Background()

		_, err := store.ChunkReader(ctx, "does-not-exist")
		assert.Error(t, err)

		_, err = store.GetMetadata(ctx, "does-not-exist")
		assert.Error(t, err)
	}
}

func testDifferentKeysAreIsolated(store *blob.Store[session.Session, *session.Session], _ *objstore.InMemBucket) func(t *testing.T) {
	return func(t *testing.T) {
		t.Helper()

		putWithContent(t, store, "iso-a", []byte("meta-a"), []byte("content-a"))
		putWithContent(t, store, "iso-b", []byte("meta-b"), []byte("content-b"))

		gotA := getContents(t, store, "iso-a")
		assert.Equal(t, []byte("content-a"), gotA)

		gotB := getContents(t, store, "iso-b")
		assert.Equal(t, []byte("content-b"), gotB)
	}
}

func testOverwriteExistingKey(store *blob.Store[session.Session, *session.Session], _ *objstore.InMemBucket) func(t *testing.T) {
	return func(t *testing.T) {
		t.Helper()

		putWithContent(t, store, "ow-key", []byte("meta-v1"), []byte("v1"))
		putWithContent(t, store, "ow-key", []byte("meta-v2"), []byte("v2"))

		got := getContents(t, store, "ow-key")
		assert.Equal(t, []byte("v1v2"), got)

		gotMeta, err := store.GetMetadata(t.Context(), "ow-key")
		require.NoError(t, err)
		assert.Equal(t, []byte("meta-v2"), gotMeta)
	}
}

func testEmptyContentsAndMetadata(store *blob.Store[session.Session, *session.Session], _ *objstore.InMemBucket) func(t *testing.T) {
	return func(t *testing.T) {
		t.Helper()

		putWithContent(t, store, "empty-key", nil, nil)

		gotMeta, err := store.GetMetadata(t.Context(), "empty-key")
		require.NoError(t, err)
		assert.Empty(t, gotMeta)
	}
}

func testKeysWithPathSeparators(store *blob.Store[session.Session, *session.Session], _ *objstore.InMemBucket) func(t *testing.T) {
	return func(t *testing.T) {
		t.Helper()

		putWithContent(t, store, "a/b/c", []byte("meta"), []byte("nested"))

		got := getContents(t, store, "a/b/c")
		assert.Equal(t, []byte("nested"), got)
	}
}

func mustMarshalSession(t *testing.T, s *session.Session) []byte {
	t.Helper()
	data, err := proto.Marshal(s)
	require.NoError(t, err)
	return data
}

func TestBlobStore_BucketSwapIsolatesData(t *testing.T) {
	t.Parallel()
	bucket1 := objstore.NewInMemBucket()
	store := blob.NewStore[session.Session](context.Background(), "test-prefix", blob.WithInMemory())
	store.OnConfigChange(t.Context(), bucket1)
	t.Cleanup(store.Stop)

	putWithContent(t, store, "change-key", []byte("meta-1"), []byte("data-1"))

	bucket2 := objstore.NewInMemBucket()
	store.OnConfigChange(t.Context(), bucket2)

	_, err := store.ChunkReader(t.Context(), "change-key")
	assert.Error(t, err, "data from old bucket should not be accessible")

	putWithContent(t, store, "change-key", []byte("meta-2"), []byte("data-2"))

	got := getContents(t, store, "change-key")
	assert.Equal(t, []byte("data-2"), got)
}
