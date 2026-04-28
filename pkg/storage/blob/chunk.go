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
	"strings"
	"sync"
	"time"

	"gocloud.dev/blob"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/pomerium/envoy-custom/api/x/recording"
	// register proto type for correctly setting *anpypb.Any type URL when writing/marshalling metadata
	_ "github.com/pomerium/envoy-custom/api/x/recording/formats/ssh"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/storage/blob/middleware"
)

var (
	ErrAlreadyFinalized   = errors.New("recording is already done")
	ErrMetadataMismatch   = errors.New("given metadata is different from previous metadata")
	ErrChunkWriteConflict = errors.New("chunk already exists")
	ErrChunkGap           = errors.New("chunk gap detected")
	ErrNotYetFinalized    = errors.New("recording not yet finalized for reading")
)

type chunkID int

type chunkReader struct {
	schema SchemaV1WithKey
	bucket *blob.Bucket

	readerMiddleware []middleware.ReadMiddleware
}

type chunkWriter struct {
	bucket *blob.Bucket
	schema SchemaV1WithKey

	// meant to guard for reading via the CurrentManifest() method
	// in separate go-routine while writing
	manifestMu sync.RWMutex
	manifest   *recording.ChunkManifest

	writerMiddleware []middleware.WriterMiddleware
	readerMiddleware []middleware.ReadMiddleware
}

var (
	_ ChunkWriter = (*chunkWriter)(nil)
	_ ChunkReader = (*chunkReader)(nil)
)

// Write methods

func NewChunkWriter(ctx context.Context, schema SchemaV1WithKey, bucket *blob.Bucket) (ChunkWriter, error) {
	cw := &chunkWriter{
		bucket:           bucket,
		schema:           schema,
		writerMiddleware: middleware.DefaultWriterMiddleware,
		readerMiddleware: middleware.DefaultReaderMiddleware,
	}
	if err := schema.Validate(); err != nil {
		return nil, err
	}

	locked, err := cw.isLockedForAppend(ctx)
	if err != nil {
		return nil, fmt.Errorf("check for signature: %w", err)
	}
	if locked {
		return nil, ErrAlreadyFinalized
	}

	if err := cw.loadManifest(ctx); err != nil {
		return nil, fmt.Errorf("failed to load chunk manifest: %w", err)
	}

	return cw, nil
}

func (c *chunkWriter) CurrentManifest() *recording.ChunkManifest {
	c.manifestMu.RLock()
	defer c.manifestMu.RUnlock()
	return proto.CloneOf(c.manifest)
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
	prefix := c.schema.ObjectDir() + "/recording_"
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

		base := path.Base(obj.Key)
		idStr := strings.TrimSuffix(strings.TrimPrefix(base, "recording_"), ".json")
		id, err := strconv.Atoi(idStr)
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

func (c *chunkWriter) writeOp(ctx context.Context, contentType string) (*middleware.WriteOp, error) {
	op := &middleware.WriteOp{
		Ctx:  ctx,
		Opts: &blob.WriterOptions{ContentType: contentType},
	}
	for _, mw := range c.writerMiddleware {
		if err := mw(op); err != nil {
			return nil, err
		}
	}
	return op, nil
}

func (c *chunkWriter) readOp(ctx context.Context) (*middleware.ReadOp, error) {
	op := &middleware.ReadOp{
		Ctx:  ctx,
		Opts: &blob.ReaderOptions{},
	}
	for _, mw := range c.readerMiddleware {
		if err := mw(op); err != nil {
			return nil, err
		}
	}
	return op, nil
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
	if err := c.writeMetadataOnce(ctx, mdPath, rawProto, contentType); err != nil {
		return err
	}

	rawProtoJSON, err := protojson.MarshalOptions{}.Marshal(metadata)
	if err != nil {
		return err
	}
	return c.writeMetadataOnce(ctx, jsonMdPath, rawProtoJSON, contentTypeJSON)
}

// writeOnce writes data to path if it does not already exist. If the object
// exists, it verifies the contents match and returns ErrMetadataMismatch if
// they differ.
func (c *chunkWriter) writeMetadataOnce(ctx context.Context, path string, data []byte, contentType string) error {
	exists, err := c.bucket.Exists(ctx, path)
	if err != nil {
		return err
	}
	if exists {
		readOp, err := c.readOp(ctx)
		if err != nil {
			return err
		}
		rd, err := c.bucket.NewReader(readOp.Ctx, path, readOp.Opts)
		if err != nil {
			return fmt.Errorf("read metadata %s: %w", path, err)
		}
		defer rd.Close()
		existing, err := io.ReadAll(rd)
		if err != nil {
			return fmt.Errorf("read metadata %s: %w", path, err)
		}
		if !bytes.Equal(existing, data) {
			return ErrMetadataMismatch
		}
		return nil
	}
	writeOp, err := c.writeOp(ctx, contentType)
	if err != nil {
		return err
	}
	return c.bucket.WriteAll(writeOp.Ctx, path, data, writeOp.Opts)
}

func (c *chunkWriter) WriteChunk(ctx context.Context, data []byte, checksum [16]byte) error {
	chunkPath, contentType := c.schema.ChunkPath(c.nextChunkID())
	exists, err := c.bucket.Exists(ctx, chunkPath)
	if err != nil {
		return fmt.Errorf("stat chunk %s: %w", chunkPath, err)
	}
	if exists {
		return ErrChunkWriteConflict
	}

	log.Ctx(ctx).Debug().Str("blob-path", chunkPath).Msg("writing chunk")
	writeOp, err := c.writeOp(ctx, contentType)
	if err != nil {
		return err
	}
	if err := c.bucket.WriteAll(writeOp.Ctx, chunkPath, data, writeOp.Opts); err != nil {
		return fmt.Errorf("write chunk %s: %w", chunkPath, err)
	}
	c.appendChunk(len(data), checksum)
	return nil
}

// Finalize persists the chunk manifest and signature to blob storage.
// Writing the signature marks the recording as complete and prevents further appends.
func (c *chunkWriter) Finalize(ctx context.Context, sig *recording.RecordingSignature) error {
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
	writeOp, err := c.writeOp(ctx, manifestCT)
	if err != nil {
		return err
	}
	if err := c.bucket.WriteAll(writeOp.Ctx, manifestPath, manifestData, writeOp.Opts); err != nil {
		return fmt.Errorf("write manifest: %w", err)
	}

	sigData, err := proto.Marshal(sig)
	if err != nil {
		return fmt.Errorf("marshal signature: %w", err)
	}
	sigPath, sigCT := c.schema.SignaturePath()
	log.Ctx(ctx).Debug().Str("blob-path", sigPath).Msg("writing signature")
	writeOp, err = c.writeOp(ctx, sigCT)
	if err != nil {
		return err
	}
	if err := c.bucket.WriteAll(writeOp.Ctx, sigPath, sigData, writeOp.Opts); err != nil {
		return fmt.Errorf("write signature: %w", err)
	}

	return nil
}

// Read methods

type ReaderOptions struct {
	additionalMiddleware []middleware.ReadMiddleware
	validateSignature    bool
}

type ReaderOption func(o *ReaderOptions)

func (o *ReaderOptions) Apply(opts ...ReaderOption) {
	for _, opt := range opts {
		opt(o)
	}
}

func WithAdditionalReaderMiddleware(mws ...middleware.ReadMiddleware) ReaderOption {
	return func(o *ReaderOptions) {
		o.additionalMiddleware = append(o.additionalMiddleware, mws...)
	}
}

func WithValidateSignature(toggle bool) ReaderOption {
	return func(o *ReaderOptions) {
		o.validateSignature = toggle
	}
}

// NewChunkReader returns a ChunkReader for the recording.
// It returns an error if the recording is not yet finalized
func NewChunkReader(ctx context.Context, schema SchemaV1WithKey, bucket *blob.Bucket, opts ...ReaderOption) (ChunkReader, error) {
	readerOpts := &ReaderOptions{
		validateSignature: true,
	}
	readerOpts.Apply(opts...)

	if readerOpts.validateSignature {
		path, _ := schema.SignaturePath()
		ok, err := bucket.Exists(ctx, path)
		if err != nil {
			return nil, err
		}

		if !ok {
			return nil, ErrNotYetFinalized
		}
	}
	return &chunkReader{
		schema:           schema,
		bucket:           bucket,
		readerMiddleware: append(middleware.DefaultReaderMiddleware, readerOpts.additionalMiddleware...),
	}, nil
}

func (c *chunkReader) readOp(ctx context.Context) (*middleware.ReadOp, error) {
	op := &middleware.ReadOp{
		Ctx:  ctx,
		Opts: &blob.ReaderOptions{},
	}
	for _, mw := range c.readerMiddleware {
		if err := mw(op); err != nil {
			return nil, err
		}
	}
	return op, nil
}

func (c *chunkReader) readAll(ctx context.Context, key string) ([]byte, error) {
	readOp, err := c.readOp(ctx)
	if err != nil {
		return nil, err
	}
	rd, err := c.bucket.NewReader(readOp.Ctx, key, readOp.Opts)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s : %w", key, err)
	}
	defer rd.Close()
	return io.ReadAll(rd)
}

func (c *chunkReader) getManifest(ctx context.Context) (*recording.ChunkManifest, error) {
	manifestPath, _ := c.schema.ManifestPath()
	data, err := c.readAll(ctx, manifestPath)
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
			data, err := c.readAll(ctx, chunkPath)
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

func (c *chunkReader) GetMetadata(ctx context.Context) ([]byte, error) {
	path, _ := c.schema.MetadataPath()
	return c.readAll(ctx, path)
}
