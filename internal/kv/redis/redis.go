// Package redis implements a key value store (kv.Store) using redis.
// For more details, see https://redis.io/
package redis

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"

	"github.com/go-redis/redis/v7"
	"github.com/pomerium/pomerium/internal/kv"
)

var _ kv.Store = &Store{}

// Name represents redis's shorthand name.
const Name = "redis"

// Store implements a the Store interface for redis.
// https://godoc.org/github.com/go-redis/redis
type Store struct {
	db *redis.Client
}

// Options represents options for configuring the redis store.
type Options struct {
	// host:port Addr.
	Addr string
	// Optional password. Must match the password specified in the
	// requirepass server configuration option.
	Password string
	// Database to be selected after connecting to the server.
	DB int
	// TLS Config to use. When set TLS will be negotiated.
	TLSConfig *tls.Config
}

// New creates a new redis cache store.
// It is up to the operator to make sure that the store's path
// is writeable.
func New(o *Options) (*Store, error) {
	if o.Addr == "" {
		return nil, fmt.Errorf("kv/redis: connection address is required")
	}

	db := redis.NewClient(
		&redis.Options{
			Addr:      o.Addr,
			Password:  o.Password,
			DB:        o.DB,
			TLSConfig: o.TLSConfig,
		})

	if _, err := db.Ping().Result(); err != nil {
		return nil, fmt.Errorf("kv/redis: error connecting to redis: %w", err)
	}

	return &Store{db: db}, nil
}

// Set is equivalent to redis `SET key value [expiration]` command.
//
// Use expiration for `SETEX`-like behavior.
// Zero expiration means the key has no expiration time.
func (s Store) Set(ctx context.Context, k string, v []byte) error {
	if err := s.db.Set(k, string(v), 0).Err(); err != nil {
		return err
	}
	return nil
}

// Get is equivalent to  Redis `GET key` command.
//  It returns redis.Nil error when key does not exist.
func (s *Store) Get(ctx context.Context, k string) (bool, []byte, error) {
	v, err := s.db.Get(k).Result()
	if errors.Is(err, redis.Nil) {
		return false, nil, nil
	} else if err != nil {
		return false, nil, err
	}
	return true, []byte(v), nil
}

// Close closes the client, releasing any open resources.
//
// It is rare to Close a Client, as the Client is meant to be
// long-lived and shared between many goroutines.
func (s Store) Close(ctx context.Context) error {
	return s.db.Close()
}
