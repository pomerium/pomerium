package cluster

import (
	"net/url"
	"sync"
	"time"
)

// URLCache is a cache of URLs to download bundles from.
type URLCache struct {
	mx    sync.RWMutex
	cache map[string]DownloadCacheEntry
}

// DownloadCacheEntry is a cache entry for a URL to download a bundle from.
type DownloadCacheEntry struct {
	// URL is the URL to download the bundle from.
	URL url.URL
	// ExpiresAt is the time at which the URL expires.
	ExpiresAt time.Time
	// CaptureHeaders is a list of headers to capture from the response.
	CaptureHeaders []string
}

// NewURLCache creates a new URL cache.
func NewURLCache() *URLCache {
	return &URLCache{
		cache: make(map[string]DownloadCacheEntry),
	}
}

func (c *URLCache) Delete(key string) {
	c.mx.Lock()
	defer c.mx.Unlock()

	delete(c.cache, key)
}

// Get gets the cache entry for the given key, if it exists and has not expired.
func (c *URLCache) Get(key string, minTTL time.Duration) (*DownloadCacheEntry, bool) {
	c.mx.RLock()
	defer c.mx.RUnlock()

	entry, ok := c.cache[key]
	if !ok {
		return nil, false
	}

	if time.Until(entry.ExpiresAt) < minTTL {
		return nil, false
	}

	return &entry, true
}

// Set sets the cache entry for the given key.
func (c *URLCache) Set(key string, entry DownloadCacheEntry) {
	c.mx.Lock()
	defer c.mx.Unlock()

	c.cache[key] = entry
}
