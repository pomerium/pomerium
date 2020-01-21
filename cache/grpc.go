//go:generate protoc -I ../internal/grpc/cache/ --go_out=plugins=grpc:../internal/grpc/cache/ ../internal/grpc/cache/cache.proto

package cache // import "github.com/pomerium/pomerium/cache"
import (
	"context"

	"github.com/pomerium/pomerium/internal/grpc/cache"
	"github.com/pomerium/pomerium/internal/telemetry/trace"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Get retrieves a key the cache store and returns the value, if found.
func (c *Cache) Get(ctx context.Context, in *cache.GetRequest) (*cache.GetReply, error) {
	ctx, span := trace.StartSpan(ctx, "cache.grpc.Get")
	defer span.End()
	exists, value, err := c.cache.Get(ctx, in.GetKey())
	if err != nil {
		return nil, status.Errorf(codes.Unknown, "cache.grpc.Get error: %v", err)
	}
	return &cache.GetReply{Exists: exists, Value: value}, nil
}

// Set persists a key value pair in the cache store.
func (c *Cache) Set(ctx context.Context, in *cache.SetRequest) (*cache.SetReply, error) {
	ctx, span := trace.StartSpan(ctx, "cache.grpc.Set")
	defer span.End()
	err := c.cache.Set(ctx, in.GetKey(), in.GetValue())
	if err != nil {
		return nil, status.Errorf(codes.Unknown, "cache.grpc.Set error: %v", err)
	}
	return &cache.SetReply{}, nil
}
