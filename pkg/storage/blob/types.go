package blob

//!! WIP abstractions

import (
	"context"
	"io"

	"github.com/pomerium/pomerium/config"
	"google.golang.org/protobuf/proto"
)

type ObjectReaderWriter interface {
	OnConfigChange(ctx context.Context, cfg *config.Config)
	ObjectReader
	ObjectWriter
}

type ObjectWriter interface {
	Put(ctx context.Context, key string, metadata io.Reader, contents io.Reader) error
}

type ObjectReader interface {
	GetContents(ctx context.Context, key string) ([]byte, error)
	GetMetadata(ctx context.Context, key string) ([]byte, error)
}

type ObjectQuerier[Md proto.Message] interface {
	QueryMetadata(ctx context.Context, opts ...QueryOption) ([]Md, error)
}
