package cache // import "github.com/pomerium/pomerium/cache"

import (
	"context"
	"errors"
	"fmt"
	stdlog "log"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/cryptutil"
	"github.com/pomerium/pomerium/internal/kv"
	"github.com/pomerium/pomerium/internal/kv/autocache"
	"github.com/pomerium/pomerium/internal/kv/bolt"
	"github.com/pomerium/pomerium/internal/kv/redis"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/urlutil"
)

// Cache represents the cache service. The cache service is a simple interface
// for storing keyed blobs (bytes) of unstructured data.
type Cache struct {
	cache kv.Store
}

// New creates a new cache service.
func New(opts config.Options) (*Cache, error) {
	if err := validate(opts); err != nil {
		return nil, fmt.Errorf("cache: bad option: %w", err)
	}

	cache, err := newCacheStore(opts.CacheStore, &opts)
	if err != nil {
		return nil, err
	}
	return &Cache{
		cache: cache,
	}, nil
}

// validate checks that proper configuration settings are set to create
// a cache instance
func validate(o config.Options) error {
	if _, err := cryptutil.NewAEADCipherFromBase64(o.SharedKey); err != nil {
		return fmt.Errorf("invalid 'SHARED_SECRET': %w", err)
	}
	if err := urlutil.ValidateURL(o.CacheURL); err != nil {
		return fmt.Errorf("invalid 'CACHE_SERVICE_URL': %w", err)
	}
	return nil
}

// newCacheStore creates a new cache store by name and given a set of
// configuration options.
func newCacheStore(name string, o *config.Options) (s kv.Store, err error) {
	switch name {
	case bolt.Name:
		s, err = bolt.New(&bolt.Options{Path: o.CacheStorePath})
	case redis.Name:
		s, err = redis.New(&redis.Options{
			Addr:     o.CacheStoreAddr,
			Password: o.CacheStorePassword,
		})
	case autocache.Name:
		acLog := log.Logger.With().Str("service", autocache.Name).Logger()
		s, err = autocache.New(&autocache.Options{
			SharedKey:     o.SharedKey,
			Log:           stdlog.New(acLog, "", 0),
			ClusterDomain: o.CacheURL.Hostname(),
		})
	default:
		return nil, fmt.Errorf("cache: unknown store: %s", name)
	}
	if err != nil {
		return nil, err
	}
	return s, nil
}

// Close shuts down the underlying cache store, services, or both -- if any.
func (c *Cache) Close() error {
	if c.cache == nil {
		return errors.New("cache: cannot close nil cache")
	}
	return c.cache.Close(context.TODO())
}
