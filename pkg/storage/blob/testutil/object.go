package testutil

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gblob "gocloud.dev/blob"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"

	"github.com/pomerium/envoy-custom/api/x/recording"
	"github.com/pomerium/pomerium/pkg/storage/blob"
	"github.com/pomerium/pomerium/pkg/storage/blob/middleware"
)

func testContext(t *testing.T) context.Context {
	t.Helper()
	return middleware.ContextWithBlobUserAgent(t.Context(), "pomerium-blob-testutil")
}

func TestFullObjectMatches(
	t *testing.T,
	bucket *gblob.Bucket,
	schema blob.SchemaV1WithKey,
	metadataProto *recording.RecordingData,
	manifestProto *recording.ChunkManifest,
	fullObject []byte,
	trailerProto *recording.RecordingTrailer,
) {
	t.Helper()
	require.NoError(t, schema.Validate())

	ctx := testContext(t)
	expectedMetadata := metadataProto.GetMetadata()

	mdPath, mdCT := schema.MetadataPath()
	mdBytes, mdAttrs := readWithAttrs(ctx, t, bucket, mdPath)
	assert.Equal(t, mdCT, mdAttrs.ContentType)
	storedMetadata := &recording.RecordingMetadata{}
	require.NoError(t, proto.Unmarshal(mdBytes, storedMetadata))
	assert.Empty(t, cmp.Diff(expectedMetadata, storedMetadata, protocmp.Transform()))

	jsonPath, jsonCT := schema.MetadataJSON()
	jsonBytes, jsonAttrs := readWithAttrs(ctx, t, bucket, jsonPath)
	assert.Equal(t, jsonCT, jsonAttrs.ContentType)
	storedMetadataJSON := &recording.RecordingMetadata{}
	require.NoError(t, protojson.Unmarshal(jsonBytes, storedMetadataJSON))
	assert.Empty(t, cmp.Diff(expectedMetadata, storedMetadataJSON, protocmp.Transform()))

	manifestPath, manifestCT := schema.ManifestPath()
	manifestBytes, manifestAttrs := readWithAttrs(ctx, t, bucket, manifestPath)
	assert.Equal(t, manifestCT, manifestAttrs.ContentType)
	storedManifest := &recording.ChunkManifest{}
	require.NoError(t, proto.Unmarshal(manifestBytes, storedManifest))
	assert.Empty(t, cmp.Diff(manifestProto, storedManifest, protocmp.Transform()))

	sigPath, sigCT := schema.SignaturePath()
	sigBytes, sigAttrs := readWithAttrs(ctx, t, bucket, sigPath)
	assert.Equal(t, sigCT, sigAttrs.ContentType)
	storedTrailer := &recording.RecordingTrailer{}
	require.NoError(t, proto.Unmarshal(sigBytes, storedTrailer))
	assert.Empty(t, cmp.Diff(trailerProto, storedTrailer, protocmp.Transform()), "trailer mismatch")

	var concatenated []byte
	for i := range manifestProto.GetItems() {
		chunkPath := fmt.Sprintf("%s/recording_%010d.json", schema.ObjectDir(), i)
		chunkBytes, chunkAttrs := readWithAttrs(ctx, t, bucket, chunkPath)
		assert.Equal(t, blob.ContentTypeProtojson, chunkAttrs.ContentType, "chunk %d content type", i)
		concatenated = append(concatenated, chunkBytes...)
	}
	assert.Equal(t, fullObject, concatenated, "concatenated chunk bytes")
}

func TestFullPathsMatchExactly(
	t *testing.T,
	bucket *gblob.Bucket,
	fullPaths []string,
) {
	t.Helper()

	ctx := testContext(t)
	got := []string{}
	iter := bucket.List(&gblob.ListOptions{})
	for {
		obj, err := iter.Next(ctx)
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err)
		if obj.IsDir {
			continue
		}
		got = append(got, obj.Key)
	}

	want := append([]string(nil), fullPaths...)
	sort.Strings(got)
	sort.Strings(want)
	assert.ElementsMatch(t, want, got, "object keys in bucket")
}

func TestSchemaIDsMatchExactly(
	t *testing.T,
	bucket *gblob.Bucket,
	schema blob.SchemaV1,
	ids []string,
) {
	t.Helper()

	ctx := testContext(t)
	got := []string{}
	for id, err := range blob.IterateRecordingIDs(ctx, bucket, schema) {
		require.NoError(t, err)
		got = append(got, id)
	}
	assert.ElementsMatch(t, ids, got, "recording IDs under %s", schema)
}

func readWithAttrs(ctx context.Context, t *testing.T, bucket *gblob.Bucket, key string) ([]byte, *gblob.Attributes) {
	t.Helper()
	data, err := bucket.ReadAll(ctx, key)
	require.NoError(t, err, "read %s", key)
	attrs, err := bucket.Attributes(ctx, key)
	require.NoError(t, err, "attributes %s", key)
	return data, attrs
}
