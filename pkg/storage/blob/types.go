package blob

//!! WIP abstractions

import (
	"context"
	"io"
	"iter"
	"time"

	"github.com/thanos-io/objstore"
	"google.golang.org/protobuf/proto"

	"github.com/pomerium/pomerium/pkg/grpc/recording"
)

type ObjectReaderWriter interface {
	OnConfigChange(ctx context.Context, bucket objstore.Bucket)
	ObjectReader
	ObjectWriter
}

type ObjectWriter interface {
	Start(ctx context.Context, recordingType, key string, metadata io.Reader) (ChunkWriter, error)
}

type ObjectReader interface {
	ChunkReader(ctx context.Context, recordingType, key string) (ChunkReader, error)
	GetMetadata(ctx context.Context, recordingType, key string) ([]byte, error)
}

type ObjectQuerier[T any, TMsg interface {
	*T
	proto.Message
}] interface {
	QueryMetadata(ctx context.Context, recordingType string, opts ...QueryOption) ([]MetadataWithId[T, TMsg], error)
}

// ChunkWriter manages the writing of data in chunks to blob storage.
// It maintains a manifest of written chunks
type ChunkWriter interface {
	// WriteChunk writes a single chunk of data.
	// The ChunkManifest is updated to reflect the newly written data.
	WriteChunk(ctx context.Context, data []byte, checksum [32]byte) error
	// CurrentManifest returns the current state of the chunk manifest,
	// containing metadata about all chunks written so far.
	CurrentManifest() *recording.ChunkManifest
	// Finalize (WIP idea) could verify the integrity of each chunk and that each block
	// is sequential. On error, we could clean up this recording and request the client start over
	Finalize(ctx context.Context) error
	// Abort cancels the in flight write operations
	Abort(ctx context.Context) error
}
type ChunkReader interface {
	// Chunks returns an iterator over each chunk's data in order.
	Chunks(ctx context.Context) iter.Seq2[[]byte, error]
	// Size returns the total size of all chunks as recorded in the manifest.
	Size(ctx context.Context) (uint64, error)
	// LastModified returns the last modification time of the manifest object.
	LastModified(ctx context.Context) (time.Time, error)
	// GetAll reads and concatenates all chunks into a single byte slice.
	GetAll(ctx context.Context) ([]byte, error)
}
