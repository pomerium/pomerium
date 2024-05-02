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
}

type localCache struct {
	singleflight singleflight.Group
	mu           sync.RWMutex
	m            map[string][]byte
}

// NewLocalCache creates a new Cache backed by a map.
func NewLocalCache() Cache {
	return &localCache{
		m: make(map[string][]byte),
	}
}

func (cache *localCache) GetOrUpdate(
	ctx context.Context,
	key []byte,
	update func(ctx context.Context) ([]byte, error),
) ([]byte, error) {
	strkey := string(key)

	cache.mu.RLock()
	cached, ok := cache.m[strkey]
	cache.mu.RUnlock()
	if ok {
		return cached, nil
	}

	v, err, _ := cache.singleflight.Do(strkey, func() (any, error) {
		cache.mu.RLock()
		cached, ok := cache.m[strkey]
		cache.mu.RUnlock()
		if ok {
			return cached, nil
		}

		result, err := update(ctx)
		if err != nil {
			return nil, err
		}

		cache.mu.Lock()
		cache.m[strkey] = result
		cache.mu.Unlock()

		return result, nil
	})
	if err != nil {
		return nil, err
	}
	return v.([]byte), nil
}

func (cache *localCache) Invalidate(key []byte) {
	cache.mu.Lock()
	delete(cache.m, string(key))
	cache.mu.Unlock()
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
		cache.set(key, value)
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

func (cache *globalCache) set(k, v []byte) {
	unix := time.Now().Add(cache.ttl).UnixMilli()
	item := make([]byte, len(v)+8)
	binary.LittleEndian.PutUint64(item, uint64(unix))
	copy(item[8:], v)

	cache.mu.Lock()
	cache.fastcache.Set(k, item)
	cache.mu.Unlock()
}
