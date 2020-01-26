// Package kv defines a Store interfaces that can be implemented by
// datastores to provide key value storage capabilities.
package kv

import "context"

// Store specifies a key value storage interface.
type Store interface {
	Set(ctx context.Context, key string, value []byte) error
	Get(ctx context.Context, key string) (keyExists bool, value []byte, err error)
	Close(ctx context.Context) error
}
