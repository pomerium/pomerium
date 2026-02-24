package blob

import (
	"context"
	"io"
	"iter"
	"time"

	"github.com/pomerium/envoy-custom/api/x/recording"
)

type ObjectReaderWriter interface {
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

// ChunkWriter manages WORM compliant writing of data in chunks to blob storage.
// ChunkWriter is not safe for concurrent use.
type ChunkWriter interface {
	// WriteMetadata writes the recording metadata to blob storage.
	// If metadata already exists, it verifies equality and returns
	// ErrMetadataMismatch if the new metadata differs.
	WriteMetadata(ctx context.Context, metadata *recording.RecordingMetadata) error
	// WriteChunk writes a single chunk of data.
	// The ChunkManifest is updated to reflect the newly written data.
	WriteChunk(ctx context.Context, data []byte, checksum [16]byte) error
	// CurrentManifest returns the current state of the chunk manifest,
	// containing metadata about all chunks written so far.
	CurrentManifest() *recording.ChunkManifest
	// Finalize signs the aggregate contains of the written data with information
	// about the data itself and its provenance
	Finalize(ctx context.Context, sig *recording.RecordingSignature) error
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
