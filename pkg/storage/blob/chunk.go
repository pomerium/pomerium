package blob

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"path"
	"sync"
	"time"

	"github.com/thanos-io/objstore"
	"google.golang.org/protobuf/proto"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/grpc/recording"
	"github.com/pomerium/pomerium/pkg/iterutil"
)

type chunkID int

// chunkReaderWriter provides chunked read/write access to a blob object.
// Write operations are intended to be used synchronously and write in-order.
type chunkReaderWriter struct {
	cw *chunkWriter
	cr *chunkReader
}

type chunkReader struct {
	schema schemaV1
	bucket objstore.Bucket
}

type chunkWriter struct {
	bucket objstore.Bucket

	writeCtx   context.Context
	writeCa    context.CancelFunc
	schema     schemaV1
	manifestMu sync.RWMutex
	manifest   *recording.ChunkManifest
}

type schemaV1 struct {
	basePath string
}

func asIDStr(cID chunkID) string {
	return fmt.Sprintf("%010d", cID)
}

func (c *schemaV1) manifestPath() string {
	return path.Join(c.basePath, "manifest")
}

func (c *schemaV1) chunkPath(id chunkID) string {
	return path.Join(c.basePath, asIDStr(id))
}

var (
	_ ChunkWriter = (*chunkWriter)(nil)
	_ ChunkReader = (*chunkReader)(nil)
)

func newChunkReaderWriter(ctx context.Context, basePath string, bucket objstore.Bucket) (*chunkReaderWriter, error) {
	schema := schemaV1{basePath}

	cw, err := newChunkWriter(ctx, schema, bucket)
	if err != nil {
		return nil, err
	}
	return &chunkReaderWriter{
		cw: cw,
		cr: newChunkReader(schema, bucket),
	}, nil
}

func (c *chunkReaderWriter) Reader() ChunkReader {
	return c.cr
}

func (c *chunkReaderWriter) Writer() ChunkWriter {
	return c.cw
}

// Write methods

func newChunkWriter(ctx context.Context, schema schemaV1, bucket objstore.Bucket) (*chunkWriter, error) {
	ctxca, ca := context.WithCancel(ctx)
	cw := &chunkWriter{
		bucket:   bucket,
		schema:   schema,
		writeCtx: ctxca,
		writeCa:  ca,
	}

	if err := cw.loadManifest(ctx); err != nil {
		return nil, fmt.Errorf("failed to load chunk manifest: %w", err)
	}

	return cw, nil
}

func (c *chunkWriter) currentWriterManifest() *recording.ChunkManifest {
	c.manifestMu.RLock()
	defer c.manifestMu.RUnlock()
	return proto.Clone(c.manifest).(*recording.ChunkManifest)
}

func (c *chunkWriter) CurrentManifest() *recording.ChunkManifest {
	return c.currentWriterManifest()
}

func (c *chunkWriter) loadManifest(ctx context.Context) error {
	manifestPath := c.schema.manifestPath()
	ok, err := c.bucket.Exists(ctx, manifestPath)
	if err != nil {
		return err
	}
	if !ok {
		c.manifest = new(recording.ChunkManifest)
		return nil
	}
	rc, err := c.bucket.Get(ctx, manifestPath)
	if err != nil {
		return err
	}
	data, err := io.ReadAll(rc)
	if closeErr := rc.Close(); closeErr != nil && err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	manifest := &recording.ChunkManifest{}
	if err := proto.Unmarshal(data, manifest); err != nil {
		return err
	}
	c.manifest = manifest
	return nil
}

func (c *chunkWriter) curChunk() chunkID {
	return chunkID(len(c.manifest.GetItems()))
}

func (c *chunkWriter) curPath() string {
	return c.schema.chunkPath(c.curChunk())
}

func (c *chunkWriter) appendChunk(size int, checksum [32]byte) {
	c.manifestMu.Lock()
	defer c.manifestMu.Unlock()
	c.manifest.Items = append(c.manifest.Items, &recording.ChunkMetadata{
		Size:     uint32(size),
		Checksum: checksum[:],
	})
}

func (c *chunkWriter) WriteChunk(ctx context.Context, data []byte, checksum [32]byte) error {
	chunkPath := c.curPath()
	log.Ctx(ctx).Debug().Str("chunk-id", chunkPath).Msg("writing chunk")
	if err := c.bucket.Upload(c.writeCtx, chunkPath, bytes.NewReader(data)); err != nil {
		return err
	}
	c.appendChunk(len(data), checksum)
	manifestData, err := proto.Marshal(c.manifest)
	if err != nil {
		return err
	}
	log.Ctx(ctx).Debug().Str("chunk-id", c.schema.manifestPath()).Msg("updating manifest")
	return c.bucket.Upload(c.writeCtx, c.schema.manifestPath(), bytes.NewReader(manifestData))
}

func (c *chunkWriter) Finalize(_ context.Context) error {
	// TODO : in theory we could verify the integrity of each chunk, but that may be slow
	return nil
}

func (c *chunkWriter) Abort(_ context.Context) error {
	c.writeCa()
	return nil
}

// Read methods

func newChunkReader(schema schemaV1, bucket objstore.Bucket) *chunkReader {
	return &chunkReader{
		schema: schema,
		bucket: bucket,
	}
}

func (c *chunkReader) getManifest(ctx context.Context) (*recording.ChunkManifest, error) {
	manifestPath := c.schema.manifestPath()
	rc, err := c.bucket.Get(ctx, manifestPath)
	if err != nil {
		return nil, err
	}
	data, err := io.ReadAll(rc)
	if closeErr := rc.Close(); closeErr != nil && err == nil {
		err = closeErr
	}
	if err != nil {
		return nil, err
	}
	manifest := &recording.ChunkManifest{}
	if err := proto.Unmarshal(data, manifest); err != nil {
		return nil, err
	}
	return manifest, nil
}

func (c *chunkReader) Chunks(ctx context.Context) iterutil.ErrorSeq[[]byte] {
	return func(yield func([]byte, error) bool) {
		manifest, err := c.getManifest(ctx)
		if err != nil {
			yield(nil, fmt.Errorf("load manifest: %w", err))
			return
		}
		for i := range len(manifest.GetItems()) {
			rc, err := c.bucket.Get(ctx, c.schema.chunkPath(chunkID(i)))
			if err != nil {
				yield(nil, fmt.Errorf("chunk %d: %w", i, err))
				return
			}
			data, err := io.ReadAll(rc)
			if closeErr := rc.Close(); closeErr != nil && err == nil {
				err = closeErr
			}
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
	attrs, err := c.bucket.Attributes(ctx, c.schema.manifestPath())
	if err != nil {
		return time.Time{}, fmt.Errorf("manifest attributes: %w", err)
	}
	return attrs.LastModified, nil
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
