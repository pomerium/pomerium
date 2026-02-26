package blob_test

import (
	"context"
	"crypto/md5"
	"fmt"
	"os"
	"runtime"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gblob "gocloud.dev/blob"
	_ "gocloud.dev/blob/memblob"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/pomerium/envoy-custom/api/x/recording"
	"github.com/pomerium/pomerium/internal/testutil"
	"github.com/pomerium/pomerium/pkg/storage/blob"
	"github.com/pomerium/pomerium/pkg/storage/blob/providers"
)

func emptyCheckSum() [16]byte {
	return [16]byte{}
}

func TestChunkReaderWriter(t *testing.T) {
	t.Parallel()

	t.Run("in-mem", func(t *testing.T) {
		b, err := gblob.OpenBucket(t.Context(), "mem://?prefix=a/subfolder/")
		require.NoError(t, err)
		t.Cleanup(func() { b.Close() })
		testChunkReaderWriterConformance(t,
			func(schema blob.SchemaV1WithKey) blob.ChunkReader {
				return blob.NewChunkReader(schema, b)
			},
			func(ctx context.Context, schema blob.SchemaV1WithKey) (blob.ChunkWriter, error) {
				return blob.NewChunkWriter(ctx, schema, b)
			},
			b, true,
		)
	})

	t.Run("minio-locked", func(t *testing.T) {
		endp, ak, sk, bk := setupWithObjectLock(t)

		bucketURI := fmt.Sprintf(
			"s3://%s:%s@%s?endpoint=%s&disable_https=true&use_path_style=true&region=us-east-1",
			ak, sk, bk, endp,
		)
		b, err := providers.OpenBucket(t.Context(), bucketURI)
		require.NoError(t, err)
		require.NotNil(t, b)
		testChunkReaderWriterConformance(t,
			func(schema blob.SchemaV1WithKey) blob.ChunkReader {
				return blob.NewChunkReader(schema, b)
			},
			func(ctx context.Context, schema blob.SchemaV1WithKey) (blob.ChunkWriter, error) {
				return blob.NewChunkWriter(ctx, schema, b)
			},
			b, false,
		)
	})
}

// Meta testing that the test code we write for WORM conformance is correct
func TestConformanceChecks(t *testing.T) {
	t.Run("minio-locked", func(t *testing.T) {
		endp, ak, sk, bk := setupWithObjectLock(t)

		bucketURI := fmt.Sprintf(
			"s3://%s:%s@%s?endpoint=%s&disable_https=true&use_path_style=true&region=us-east-1",
			ak, sk, bk, endp,
		)
		b, err := providers.OpenBucket(t.Context(), bucketURI)
		require.NoError(t, err)

		require.NoError(t, b.WriteAll(t.Context(), "foo", []byte("foo"), &gblob.WriterOptions{}))
		require.NoError(t, b.WriteAll(t.Context(), "foo", []byte("bar"), &gblob.WriterOptions{}))

		data, err := b.ReadAll(t.Context(), "foo")
		require.NoError(t, err)
		require.Equal(t, []byte("bar"), data)
		verifyWroteOnceSemantics(t, b, false)
	})
}

func testChunkReaderWriterConformance(t *testing.T,
	rF func(blob.SchemaV1WithKey) blob.ChunkReader,
	wrF func(context.Context, blob.SchemaV1WithKey) (blob.ChunkWriter, error),
	bk *gblob.Bucket,
	skipLockCheck bool,
) {
	t.Helper()
	// required wrapper without t.Parallel() so that the integrity checks run after each case
	t.Run("", func(t *testing.T) {
		// starts chunked writer and goes to completion (metadata->chunks->sig/manifest)
		t.Run("chunked upload", func(t *testing.T) {
			t.Parallel()
			schema := blob.NewSchemaV1WithKey(blob.SchemaV1{}, "id1")
			ctx := t.Context()

			cw, err := wrF(ctx, schema)
			require.NoError(t, err)

			md := &recording.RecordingMetadata{Id: "rec-1", RecordingType: recording.RecordingFormat_RecordingFormatUnknown}
			require.NoError(t, cw.WriteMetadata(ctx, md))

			chunk1 := []byte("foo")
			chunk2 := []byte("bar")
			chunk3 := []byte("baz")
			require.NoError(t, cw.WriteChunk(ctx, chunk1, emptyCheckSum()))
			require.NoError(t, cw.WriteChunk(ctx, chunk2, emptyCheckSum()))
			require.NoError(t, cw.WriteChunk(ctx, chunk3, emptyCheckSum()))

			require.NoError(t, cw.Finalize(ctx, &recording.RecordingSignature{}))

			mdPath, _ := schema.MetadataPath()
			rawMd, err := bk.ReadAll(ctx, mdPath)
			require.NoError(t, err)
			existingMd := &recording.RecordingMetadata{}
			require.NoError(t, proto.Unmarshal(rawMd, existingMd))
			assert.Equal(t, md.GetId(), existingMd.GetId())
			assert.Equal(t, md.GetRecordingType(), existingMd.GetRecordingType())

			jsonMdPath, _ := schema.MetadataJSON()
			rawJSONMD, err := bk.ReadAll(ctx, jsonMdPath)
			require.NoError(t, err)
			jsonExistingMd := &recording.RecordingMetadata{}
			require.NoError(t, protojson.Unmarshal(rawJSONMD, jsonExistingMd))
			assert.Equal(t, md.GetId(), jsonExistingMd.GetId())
			assert.Equal(t, md.GetRecordingType(), jsonExistingMd.GetRecordingType())

			cr := rF(schema)
			all, err := cr.GetAll(ctx)
			require.NoError(t, err)
			assert.Equal(t, []byte("foobarbaz"), all)

			size, err := cr.Size(ctx)
			require.NoError(t, err)
			assert.Equal(t, uint64(len([]byte("foobarbaz"))), size)

			lastMod, err := cr.LastModified(ctx)
			require.NoError(t, err)
			assert.False(t, lastMod.IsZero())

			var chunks [][]byte
			for data, err := range cr.Chunks(ctx) {
				require.NoError(t, err)
				chunks = append(chunks, data)
			}
			assert.Equal(t, [][]byte{[]byte("foo"), []byte("bar"), []byte("baz")}, chunks)

			// chunks early break exercises the !yield path
			count := 0
			for _, err := range cr.Chunks(ctx) {
				require.NoError(t, err)
				count++
				break
			}
			assert.Equal(t, 1, count)

			sigPath, _ := schema.SignaturePath()
			sigExists, err := bk.Exists(ctx, sigPath)
			require.NoError(t, err)
			assert.True(t, sigExists)

			_, err = wrF(ctx, schema)
			require.ErrorIs(t, err, blob.ErrAlreadyFinalized)

			// check all content types of written obejcts
			mdAttrs, err := bk.Attributes(ctx, mdPath)
			require.NoError(t, err)
			assert.Equal(t, blob.ContentTypeProtobuf, mdAttrs.ContentType, "metadata proto content type")

			jsonMdAttrs, err := bk.Attributes(ctx, jsonMdPath)
			require.NoError(t, err)
			assert.Equal(t, blob.ContentTypeJSON, jsonMdAttrs.ContentType, "metadata json content type")

			for i := range 3 {
				chunkPath := schema.ObjectPath() + "/" + fmt.Sprintf("%010d", i)
				chunkAttrs, err := bk.Attributes(ctx, chunkPath)
				require.NoError(t, err)
				assert.Equal(t, blob.ContentTypeProtobuf, chunkAttrs.ContentType, "chunk %d content type", i)
			}

			manifestPath, expectedManifestCT := schema.ManifestPath()
			manifestAttrs, err := bk.Attributes(ctx, manifestPath)
			require.NoError(t, err)
			assert.Equal(t, expectedManifestCT, manifestAttrs.ContentType, "manifest content type")

			sigAttrs, err := bk.Attributes(ctx, sigPath)
			require.NoError(t, err)
			assert.Equal(t, blob.ContentTypeProtobuf, sigAttrs.ContentType, "signature content type")
		})

		t.Run("resume", func(t *testing.T) {
			t.Parallel()
			schema := blob.NewSchemaV1WithKey(blob.SchemaV1{}, "resume")
			ctx := t.Context()

			cw1, err := wrF(ctx, schema)
			require.NoError(t, err)
			require.NoError(t, cw1.WriteChunk(ctx, []byte("foo"), emptyCheckSum()))

			// after resume, loadManifest rebuilds manifest from listed objects.
			// the checksums come from obj.MD5 computed by the blob provider on write.
			cw2, err := wrF(ctx, schema)
			require.NoError(t, err)

			expectedMD5 := md5.Sum([]byte("foo"))
			resumedManifest := cw2.CurrentManifest()
			require.Len(t, resumedManifest.GetItems(), 1, "resumed writer should see 1 existing chunk")
			assert.Equal(t, uint32(len("foo")), resumedManifest.GetItems()[0].GetSize())
			assert.Equal(t, expectedMD5[:], resumedManifest.GetItems()[0].GetChecksum(), "resumed chunk checksum should be MD5 of chunk data")

			require.NoError(t, cw2.WriteChunk(ctx, []byte("bar"), emptyCheckSum()))
			require.NoError(t, cw2.Finalize(ctx, &recording.RecordingSignature{}))

			cr := rF(schema)
			all, err := cr.GetAll(ctx)
			require.NoError(t, err)
			assert.Equal(t, []byte("foobar"), all)
		})

		t.Run("metadata conflict", func(t *testing.T) {
			t.Parallel()
			schema := blob.NewSchemaV1WithKey(blob.SchemaV1{}, "metadata-conflict")
			ctx := t.Context()

			cw1, err := wrF(ctx, schema)
			require.NoError(t, err)
			md1 := &recording.RecordingMetadata{Id: "rec-1"}
			require.NoError(t, cw1.WriteMetadata(ctx, md1))

			cw2, err := wrF(ctx, schema)
			require.NoError(t, err)
			md2 := &recording.RecordingMetadata{Id: "rec-2"}
			err = cw2.WriteMetadata(ctx, md2)
			require.ErrorIs(t, err, blob.ErrMetadataMismatch)

			cw3, err := wrF(ctx, schema)
			require.NoError(t, err)
			require.NoError(t, cw3.WriteMetadata(ctx, md1))
		})

		t.Run("chunk conflict", func(t *testing.T) {
			t.Parallel()
			schema := blob.NewSchemaV1WithKey(blob.SchemaV1{}, "chunk-conflict")
			ctx := t.Context()

			cw1, err := wrF(ctx, schema)
			require.NoError(t, err)
			cw2, err := wrF(ctx, schema)
			require.NoError(t, err)

			require.NoError(t, cw1.WriteChunk(ctx, []byte("first"), emptyCheckSum()))

			err = cw2.WriteChunk(ctx, []byte("first-but-modified"), emptyCheckSum())
			require.ErrorIs(t, err, blob.ErrChunkWriteConflict)
		})

		t.Run("already locked for appending", func(t *testing.T) {
			t.Parallel()
			schema := blob.NewSchemaV1WithKey(blob.SchemaV1{}, "already-locked")
			ctx := t.Context()

			cw, err := wrF(ctx, schema)
			require.NoError(t, err)
			require.NoError(t, cw.WriteChunk(ctx, []byte("data"), emptyCheckSum()))
			require.NoError(t, cw.Finalize(ctx, &recording.RecordingSignature{}))

			_, err = wrF(ctx, schema)
			require.ErrorIs(t, err, blob.ErrAlreadyFinalized)
		})

		t.Run("chunk gap detection", func(t *testing.T) {
			t.Parallel()
			schema := blob.NewSchemaV1WithKey(blob.SchemaV1{}, "gap")
			ctx := t.Context()

			// Write chunk 0 and chunk 2 directly to the bucket, skipping chunk 1.
			chunk0Path, ct0 := schema.ChunkPath(0)
			require.NoError(t, bk.WriteAll(ctx, chunk0Path, []byte("chunk0"), &gblob.WriterOptions{ContentType: ct0}))
			chunk2Path, ct2 := schema.ChunkPath(2)
			require.NoError(t, bk.WriteAll(ctx, chunk2Path, []byte("chunk2"), &gblob.WriterOptions{ContentType: ct2}))

			_, err := wrF(ctx, schema)
			require.ErrorIs(t, err, blob.ErrChunkGap)
		})
	})

	if !skipLockCheck {
		verifyWroteOnceSemantics(t, bk, true)
		t.Log("verified objects have a unique version")
	}
}

func verifyWroteOnceSemantics(t *testing.T, bk *gblob.Bucket, expectLocked bool) {
	t.Helper()
	var s3b *s3.Client
	checked := 0
	switch {
	case bk.As(&s3b):
		resp, err := s3b.ListObjectVersions(t.Context(), &s3.ListObjectVersionsInput{
			Bucket: aws.String("test-bucket"),
			Prefix: aws.String(""),
		})
		require.NoError(t, err)
		objVersions := make(map[string][]string)
		for _, md := range resp.Versions {
			checked++
			objVersions[*md.Key] = append(objVersions[*md.Key], *md.VersionId)
		}
		for key, versions := range objVersions {
			if expectLocked {
				assert.Len(t, versions, 1, "object %q has more than 1 version", key)
			} else {
				assert.Greater(t, len(versions), 1, "object %q does not have multiple versions", key)
			}
		}
	default:
		t.Fatal("verifyWroteOnceSemantics: bucket provider does not support version tracking; add support or use a versioned provider")
	}
	require.Greater(t, checked, 0, "no objects were actually tested when checking for versions")
}

func setupWithObjectLock(t *testing.T) (endpoint, accessKey, secretKey, bucket string) {
	if os.Getenv("GITHUB_ACTION") != "" && runtime.GOOS == "darwin" {
		t.Skip("Github action can not run docker on MacOS")
	}

	endpoint, ak, sk := testutil.StartMinio(t)

	ctx := context.Background()

	client, err := minio.New(endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(ak, sk, ""),
		Secure: false,
	})
	require.NoError(t, err)

	// Create bucket with object lock enabled
	opts := minio.MakeBucketOptions{
		ObjectLocking: true,
	}
	bk := "test-bucket"
	require.NoError(t, client.MakeBucket(ctx, bk, opts))

	// sets the default retention policy so all new objects are locked on upload
	// !! Note this doesn't preventing writing to the same object - objects will have different versions.
	mode := minio.Compliance
	validity := uint(1)
	unit := minio.Days
	require.NoError(t, client.SetObjectLockConfig(ctx, bk, &mode, &validity, &unit))

	return endpoint, ak, sk, bk
}
