package blob

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"iter"
	"path"
	"strconv"
	"sync"
	"time"

	"gocloud.dev/blob"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/pomerium/envoy-custom/api/x/recording"
	"github.com/pomerium/pomerium/internal/log"
)

var (
	ErrAlreadyFinalized   = errors.New("recording is already done")
	ErrMetadataMismatch   = errors.New("given metadata is different from previous metadata")
	ErrChunkWriteConflict = errors.New("chunk already exists")
	ErrChunkGap           = errors.New("chunk gap detected")
)

type chunkID int

type chunkReader struct {
	schema SchemaV1WithKey
	bucket *blob.Bucket
}

type chunkWriter struct {
	bucket *blob.Bucket

	writeCtx context.Context
	writeCa  context.CancelFunc
	schema   SchemaV1WithKey

	// meant to guard for reading via the CurrentManifest() method
	// in separate go-routine while writing
	manifestMu sync.RWMutex
	manifest   *recording.ChunkManifest
}

var (
	_ ChunkWriter = (*chunkWriter)(nil)
	_ ChunkReader = (*chunkReader)(nil)
)

// Write methods

func NewChunkWriter(ctx context.Context, schema SchemaV1WithKey, bucket *blob.Bucket) (ChunkWriter, error) {
	ctxca, ca := context.WithCancel(ctx)
	cw := &chunkWriter{
		bucket:   bucket,
		schema:   schema,
		writeCtx: ctxca,
		writeCa:  ca,
	}

	locked, err := cw.isLockedForAppend(ctx)
	if err != nil {
		_ = cw.Abort(ctx)
		return nil, fmt.Errorf("check for signature: %w", err)
	}
	if locked {
		return nil, ErrAlreadyFinalized
	}

	if err := cw.loadManifest(ctx); err != nil {
		_ = cw.Abort(ctx)
		return nil, fmt.Errorf("failed to load chunk manifest: %w", err)
	}

	return cw, nil
}

func (c *chunkWriter) CurrentManifest() *recording.ChunkManifest {
	c.manifestMu.RLock()
	defer c.manifestMu.RUnlock()
	return proto.Clone(c.manifest).(*recording.ChunkManifest)
}

type manifestInfo struct {
	size     int64
	checksum []byte
}

// loadManifest discovers existing chunks by listing objects under the recording
// prefix. This is the source of truth rather than a persisted manifest, because
// in WORM buckets a crash between writing chunks and persisting the manifest
// would leave chunks that the manifest doesn't know about.
func (c *chunkWriter) loadManifest(ctx context.Context) error {
	prefix := c.schema.ObjectPath() + "/"
	iter := c.bucket.List(&blob.ListOptions{
		Prefix: prefix,
	})

	chunkInfo := make(map[chunkID]manifestInfo)
	maxID := chunkID(-1)

	for {
		obj, err := iter.Next(ctx)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("list objects under %s: %w", prefix, err)
		}
		if obj.IsDir {
			continue
		}

		// Only consider objects whose basename parses as a chunk ID integer.
		// This skips manifest, signature, and any other non-chunk objects.
		base := path.Base(obj.Key)
		id, err := strconv.Atoi(base)
		if err != nil {
			continue
		}

		cid := chunkID(id)
		chunkInfo[cid] = manifestInfo{
			size:     obj.Size,
			checksum: obj.MD5,
		}
		if cid > maxID {
			maxID = cid
		}
	}

	manifest := &recording.ChunkManifest{}
	for i := chunkID(0); i <= maxID; i++ {
		info, ok := chunkInfo[i]
		if !ok {
			return ErrChunkGap
		}
		manifest.Items = append(manifest.Items, &recording.ChunkMetadata{
			Size:     uint32(info.size),
			Checksum: info.checksum,
		})
	}

	c.manifestMu.Lock()
	defer c.manifestMu.Unlock()
	c.manifest = manifest
	return nil
}

func (c *chunkWriter) nextChunkID() chunkID {
	c.manifestMu.RLock()
	defer c.manifestMu.RUnlock()
	return chunkID(len(c.manifest.GetItems()))
}

func (c *chunkWriter) appendChunk(size int, checksum [16]byte) {
	c.manifestMu.Lock()
	defer c.manifestMu.Unlock()
	c.manifest.Items = append(c.manifest.Items, &recording.ChunkMetadata{
		Size:     uint32(size),
		Checksum: checksum[:],
	})
}

func (c *chunkWriter) isLockedForAppend(ctx context.Context) (locked bool, err error) {
	sigPath, _ := c.schema.SignaturePath()
	ok, err := c.bucket.Exists(ctx, sigPath)
	if err != nil {
		return true, err
	}
	return ok, nil
}

func (c *chunkWriter) WriteMetadata(ctx context.Context, metadata *recording.RecordingMetadata) error {
	mdPath, contentType := c.schema.MetadataPath()
	jsonMdPath, contentTypeJSON := c.schema.MetadataJSON()

	rawProto, err := proto.MarshalOptions{Deterministic: true}.Marshal(metadata)
	if err != nil {
		return err
	}
	if err := c.writeOnce(ctx, mdPath, rawProto, contentType); err != nil {
		return err
	}

	rawProtoJSON, err := protojson.MarshalOptions{}.Marshal(metadata)
	if err != nil {
		return err
	}
	return c.writeOnce(ctx, jsonMdPath, rawProtoJSON, contentTypeJSON)
}

// writeOnce writes data to path if it does not already exist. If the object
// exists, it verifies the contents match and returns ErrMetadataMismatch if
// they differ.
func (c *chunkWriter) writeOnce(ctx context.Context, path string, data []byte, contentType string) error {
	exists, err := c.bucket.Exists(ctx, path)
	if err != nil {
		return err
	}
	if exists {
		existing, err := c.bucket.ReadAll(ctx, path)
		if err != nil {
			return fmt.Errorf("read existing %s: %w", path, err)
		}
		if !bytes.Equal(existing, data) {
			return ErrMetadataMismatch
		}
		return nil
	}
	return c.bucket.WriteAll(c.writeCtx, path, data, &blob.WriterOptions{
		ContentType: contentType,
	})
}

func (c *chunkWriter) WriteChunk(ctx context.Context, data []byte, checksum [16]byte) error {
	chunkPath, contentType := c.schema.ChunkPath(c.nextChunkID())
	exists, err := c.bucket.Exists(c.writeCtx, chunkPath)
	if err != nil {
		return fmt.Errorf("stat chunk %s: %w", chunkPath, err)
	}
	if exists {
		return ErrChunkWriteConflict
	}

	log.Ctx(ctx).Debug().Str("blob-path", chunkPath).Msg("writing chunk")
	if err := c.bucket.WriteAll(c.writeCtx, chunkPath, data, &blob.WriterOptions{
		ContentType: contentType,
	}); err != nil {
		return fmt.Errorf("write chunk %s: %w", chunkPath, err)
	}
	c.appendChunk(len(data), checksum)
	return nil
}

// Finalize persists the chunk manifest and signature to blob storage.
// Writing the signature marks the recording as complete and prevents further appends.
func (c *chunkWriter) Finalize(ctx context.Context, sig *recording.RecordingSignature) error {
	defer c.writeCa()
	locked, err := c.isLockedForAppend(ctx)
	if err != nil {
		return err
	}
	if locked {
		return ErrAlreadyFinalized
	}

	c.manifestMu.RLock()
	defer c.manifestMu.RUnlock()
	manifestData, err := proto.Marshal(c.manifest)
	if err != nil {
		return fmt.Errorf("marshal manifest: %w", err)
	}

	manifestPath, manifestCT := c.schema.ManifestPath()
	log.Ctx(ctx).Debug().Str("blob-path", manifestPath).Msg("writing manifest")
	if err := c.bucket.WriteAll(c.writeCtx, manifestPath, manifestData, &blob.WriterOptions{
		ContentType: manifestCT,
	}); err != nil {
		return fmt.Errorf("write manifest: %w", err)
	}

	sigData, err := proto.Marshal(sig)
	if err != nil {
		return fmt.Errorf("marshal signature: %w", err)
	}
	sigPath, sigCT := c.schema.SignaturePath()
	log.Ctx(ctx).Debug().Str("blob-path", sigPath).Msg("writing signature")
	if err := c.bucket.WriteAll(c.writeCtx, sigPath, sigData, &blob.WriterOptions{
		ContentType: sigCT,
	}); err != nil {
		return fmt.Errorf("write signature: %w", err)
	}

	return nil
}

func (c *chunkWriter) Abort(_ context.Context) error {
	c.writeCa()
	return nil
}

// Read methods

func NewChunkReader(schema SchemaV1WithKey, bucket *blob.Bucket) ChunkReader {
	return &chunkReader{
		schema: schema,
		bucket: bucket,
	}
}

func (c *chunkReader) getManifest(ctx context.Context) (*recording.ChunkManifest, error) {
	manifestPath, _ := c.schema.ManifestPath()
	data, err := c.bucket.ReadAll(ctx, manifestPath)
	if err != nil {
		return nil, fmt.Errorf("read manifest: %w", err)
	}
	manifest := &recording.ChunkManifest{}
	if err := proto.Unmarshal(data, manifest); err != nil {
		return nil, fmt.Errorf("unmarshal manifest: %w", err)
	}
	return manifest, nil
}

func (c *chunkReader) Chunks(ctx context.Context) iter.Seq2[[]byte, error] {
	return func(yield func([]byte, error) bool) {
		manifest, err := c.getManifest(ctx)
		if err != nil {
			yield(nil, fmt.Errorf("load manifest: %w", err))
			return
		}
		for i := range len(manifest.GetItems()) {
			chunkPath, _ := c.schema.ChunkPath(chunkID(i))
			data, err := c.bucket.ReadAll(ctx, chunkPath)
			if err != nil {
				yield(nil, fmt.Errorf("chunk %d: %w", i, err))
				return
			}
			if !yield(data, nil) {
				return
			}
		}
	}
}

func (c *chunkReader) Size(ctx context.Context) (uint64, error) {
	manifest, err := c.getManifest(ctx)
	if err != nil {
		return 0, err
	}
	var total uint64
	for _, item := range manifest.GetItems() {
		total += uint64(item.GetSize())
	}
	return total, nil
}

func (c *chunkReader) LastModified(ctx context.Context) (time.Time, error) {
	manifestPath, _ := c.schema.ManifestPath()
	attrs, err := c.bucket.Attributes(ctx, manifestPath)
	if err != nil {
		return time.Time{}, fmt.Errorf("manifest attributes: %w", err)
	}
	return attrs.ModTime, nil
}

func (c *chunkReader) GetAll(ctx context.Context) ([]byte, error) {
	n, err := c.Size(ctx)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, 0, n)
	for data, err := range c.Chunks(ctx) {
		if err != nil {
			return nil, err
		}
		buf = append(buf, data...)
	}
	return buf, nil
}
