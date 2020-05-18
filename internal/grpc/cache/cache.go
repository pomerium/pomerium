// Package cache defines a Cacher interfaces that can be implemented by any
// key value store system.
package cache

import (
	"context"
)

// Cacher specifies an interface for remote clients connecting to the cache service.
type Cacher interface {
	Get(ctx context.Context, key string) (value []byte, err error)
	Set(ctx context.Context, key string, value []byte) error
	Close() error
}
