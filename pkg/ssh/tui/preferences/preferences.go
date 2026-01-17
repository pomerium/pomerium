package preferences

import (
	"sync"

	lru "github.com/hashicorp/golang-lru/v2"
)

type Preferences interface {
	Get(key string) (any, bool)
	Put(key string, value any)
	Delete(key string)
}

type inMemoryPreferences struct {
	mu    sync.Mutex
	store map[string]any
}

// Get implements Preferences.
func (i *inMemoryPreferences) Get(key string) (any, bool) {
	i.mu.Lock()
	defer i.mu.Unlock()
	v, ok := i.store[key]
	return v, ok
}

// Put implements Preferences.
func (i *inMemoryPreferences) Put(key string, value any) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.store[key] = value
}

// Delete implements Preferences.
func (i *inMemoryPreferences) Delete(key string) {
	i.mu.Lock()
	defer i.mu.Unlock()
	delete(i.store, key)
}

type Store interface {
	Load(uid string) Preferences
	Delete(uid string)
}

type preferencesStore struct {
	mu    sync.Mutex
	cache *lru.Cache[string, Preferences]
}

const maxInMemoryPreferences = 1000

func NewInMemoryStore() Store {
	cache, err := lru.New[string, Preferences](maxInMemoryPreferences)
	if err != nil {
		panic(err)
	}
	return &preferencesStore{
		cache: cache,
	}
}

func (ps *preferencesStore) Load(uid string) Preferences {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	v, ok := ps.cache.Get(uid)
	if !ok {
		prefs := &inMemoryPreferences{
			store: map[string]any{},
		}
		ps.cache.Add(uid, prefs)
		return prefs
	}
	return v
}

func (ps *preferencesStore) Delete(uid string) {
	ps.cache.Remove(uid)
}

func GetOrDefault[T any](prefs Preferences, key string, def T) T {
	if v, found := prefs.Get(key); !found {
		return def
	} else {
		t, ok := v.(T)
		if !ok {
			return def
		}
		return t
	}
}

func TestAndSetFlag(prefs Preferences, key string) bool {
	if v, found := prefs.Get(key); found {
		b, _ := v.(bool)
		if b {
			return true
		}
	}
	prefs.Put(key, true)
	return false
}
