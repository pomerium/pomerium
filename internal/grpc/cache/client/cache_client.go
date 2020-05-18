// Package client implements a gRPC client for the cache service.
package client

import (
	"context"
	"errors"

	"github.com/pomerium/pomerium/internal/grpc/cache"
	"github.com/pomerium/pomerium/internal/telemetry/trace"

	"google.golang.org/grpc"
)

var errKeyNotFound = errors.New("cache/client: key not found")

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
func (a *Client) Get(ctx context.Context, key string) (value []byte, err error) {
	ctx, span := trace.StartSpan(ctx, "grpc.cache.client.Get")
	defer span.End()

	response, err := a.client.Get(ctx, &cache.GetRequest{Key: key})
	if err != nil {
		return nil, err
	}
	if !response.GetExists() {
		return nil, errKeyNotFound
	}
	return response.GetValue(), nil
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
