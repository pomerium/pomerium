// Package client implements a gRPC client for the cache service.
package client

import (
	"context"

	"github.com/pomerium/pomerium/internal/grpc/cache"
	"github.com/pomerium/pomerium/internal/telemetry/trace"

	"google.golang.org/grpc"
)

// Cacher specifies an interface for remote clients connecting to the cache service.
type Cacher interface {
	Get(ctx context.Context, key string) (keyExists bool, value []byte, err error)
	Set(ctx context.Context, key string, value []byte) error
	Close() error
}

// Client represents a gRPC cache service client.
type Client struct {
	conn   *grpc.ClientConn
	client cache.CacheClient
}

// New returns a new gRPC cache service client.
func New(conn *grpc.ClientConn) (p *Client) {
	return &Client{conn: conn, client: cache.NewCacheClient(conn)}
}

// Get retrieves a value from the cache service.
func (a *Client) Get(ctx context.Context, key string) (keyExists bool, value []byte, err error) {
	ctx, span := trace.StartSpan(ctx, "grpc.cache.client.Get")
	defer span.End()

	response, err := a.client.Get(ctx, &cache.GetRequest{Key: key})
	if err != nil {
		return false, nil, err
	}
	return response.GetExists(), response.GetValue(), nil
}

// Set stores a key value pair in the cache service.
func (a *Client) Set(ctx context.Context, key string, value []byte) error {
	ctx, span := trace.StartSpan(ctx, "grpc.cache.client.Set")
	defer span.End()

	_, err := a.client.Set(ctx, &cache.SetRequest{Key: key, Value: value})
	if err != nil {
		return err
	}
	return nil
}

// Close tears down the ClientConn and all underlying connections.
func (a *Client) Close() error {
	return a.conn.Close()
}
