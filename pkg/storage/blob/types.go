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
	Start(ctx context.Context, key string, metadata io.Reader) (ChunkWriter, error)
}

type ObjectReader interface {
	ChunkReader(ctx context.Context, key string) (ChunkReader, error)
	GetMetadata(ctx context.Context, key string) ([]byte, error)
}

type ObjectQuerier[T any, TMsg interface {
	*T
	proto.Message
}] interface {
	QueryMetadata(ctx context.Context, opts ...QueryOption) ([]TMsg, error)
}

type ChunkWriter interface {
	WriteChunk(ctx context.Context, data []byte, checksum [32]byte) error
	CurrentManifest() *recording.ChunkManifest
	Finalize(ctx context.Context) error
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
