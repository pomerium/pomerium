package reconciler

import (
	"context"
	"errors"
	"time"
)

// BundleCacheEntry is a cache entry for a bundle
// that is kept in the databroker to avoid downloading
// the same bundle multiple times.
//
// by using the ETag and LastModified headers, we do not need to
// keep caches of the bundles themselves, which can be large.
//
// also it works in case of multiple instances, as it uses
// the databroker database as a shared cache.
type BundleCacheEntry struct {
	ETag         string
	LastModified time.Time
	RecordTypes  []string
}

var (
	// ErrBundleCacheEntryNotFound is returned when a bundle cache entry is not found
	ErrBundleCacheEntryNotFound = errors.New("bundle cache entry not found")
)

// Equals returns true if the two cache entries are equal
func (c *BundleCacheEntry) Equals(other BundleCacheEntry) bool {
	return c.ETag == other.ETag && c.LastModified.Equal(other.LastModified)
}

// GetBundleCacheEntry gets a bundle cache entry from the databroker
func (c *service) GetBundleCacheEntry(_ context.Context, _ string, _ *BundleCacheEntry) error {
	// TODO: implement
	return ErrBundleCacheEntryNotFound
}

// SetBundleCacheEntry sets a bundle cache entry in the databroker
func (c *service) SetBundleCacheEntry(_ context.Context, _ string, _ BundleCacheEntry) error {
	// TODO: implement
	return nil
}
