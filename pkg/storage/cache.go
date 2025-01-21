package storage

import (
	"context"
	"encoding/binary"
	"sync"
	"time"

	"github.com/VictoriaMetrics/fastcache"
	"golang.org/x/sync/singleflight"
)

// A Cache will return cached data when available or call update when not.
type Cache interface {
	GetOrUpdate(
		ctx context.Context,
		key []byte,
		update func(ctx context.Context) ([]byte, error),
	) ([]byte, error)
	Invalidate(key []byte)
	InvalidateAll()
	Set(expiry time.Time, key, value []byte)
}

type globalCache struct {
	ttl time.Duration

	singleflight singleflight.Group
	mu           sync.RWMutex
	fastcache    *fastcache.Cache
}

// NewGlobalCache creates a new Cache backed by fastcache and a TTL.
func NewGlobalCache(ttl time.Duration) Cache {
	return &globalCache{
		ttl:       ttl,
		fastcache: fastcache.New(256 * 1024 * 1024), // up to 256MB of RAM
	}
}

func (cache *globalCache) GetOrUpdate(
	ctx context.Context,
	key []byte,
	update func(ctx context.Context) ([]byte, error),
) ([]byte, error) {
	now := time.Now()
	data, expiry, ok := cache.get(key)
	if ok && now.Before(expiry) {
		return data, nil
	}

	v, err, _ := cache.singleflight.Do(string(key), func() (any, error) {
		data, expiry, ok := cache.get(key)
		if ok && now.Before(expiry) {
			return data, nil
		}

		value, err := update(ctx)
		if err != nil {
			return nil, err
		}
		cache.set(time.Now().Add(cache.ttl), key, value)
		return value, nil
	})
	if err != nil {
		return nil, err
	}
	return v.([]byte), nil
}

func (cache *globalCache) Invalidate(key []byte) {
	cache.mu.Lock()
	cache.fastcache.Del(key)
	cache.mu.Unlock()
}

func (cache *globalCache) InvalidateAll() {
	cache.mu.Lock()
	cache.fastcache.Reset()
	cache.mu.Unlock()
}

func (cache *globalCache) Set(expiry time.Time, key, value []byte) {
	cache.set(expiry, key, value)
}

func (cache *globalCache) get(k []byte) (data []byte, expiry time.Time, ok bool) {
	cache.mu.RLock()
	item := cache.fastcache.Get(nil, k)
	cache.mu.RUnlock()
	if len(item) < 8 {
		return data, expiry, false
	}

	unix, data := binary.LittleEndian.Uint64(item), item[8:]
	expiry = time.UnixMilli(int64(unix))
	return data, expiry, true
}

func (cache *globalCache) set(expiry time.Time, key, value []byte) {
	unix := expiry.UnixMilli()
	item := make([]byte, len(value)+8)
	binary.LittleEndian.PutUint64(item, uint64(unix))
	copy(item[8:], value)

	cache.mu.Lock()
	cache.fastcache.Set(key, item)
	cache.mu.Unlock()
}
