package cliutil

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/martinlindhe/base36"
	"golang.org/x/crypto/blake2s"
	"gopkg.in/square/go-jose.v2"
)

// predefined cache errors
var (
	ErrExpired  = errors.New("expired")
	ErrInvalid  = errors.New("invalid")
	ErrNotFound = errors.New("not found")
)

// A JWTCache loads and stores JWTs.
type JWTCache interface {
	LoadJWT(key string) (rawJWT string, err error)
	StoreJWT(key string, rawJWT string) error
}

// A LocalJWTCache stores files in the user's cache directory.
type LocalJWTCache struct {
	dir string
}

// NewLocalJWTCache creates a new LocalJWTCache.
func NewLocalJWTCache() (*LocalJWTCache, error) {
	root, err := os.UserCacheDir()
	if err != nil {
		return nil, err
	}

	dir := filepath.Join(root, "pomerium-cli", "jwts")

	err = os.MkdirAll(dir, 0755)
	if err != nil {
		return nil, fmt.Errorf("error creating user cache directory: %w", err)
	}

	return &LocalJWTCache{
		dir: dir,
	}, nil
}

// LoadJWT loads a raw JWT from the local cache.
func (cache *LocalJWTCache) LoadJWT(key string) (rawJWT string, err error) {
	path := filepath.Join(cache.dir, cache.fileName(key))
	rawBS, err := ioutil.ReadFile(path)
	if os.IsNotExist(err) {
		return "", ErrNotFound
	} else if err != nil {
		return "", err
	}
	rawJWT = string(rawBS)

	return rawJWT, checkExpiry(rawJWT)
}

// StoreJWT stores a raw JWT in the local cache.
func (cache *LocalJWTCache) StoreJWT(key string, rawJWT string) error {
	path := filepath.Join(cache.dir, cache.fileName(key))
	err := ioutil.WriteFile(path, []byte(rawJWT), 0600)
	if err != nil {
		return err
	}

	return nil
}

func (cache *LocalJWTCache) hash(str string) string {
	h := blake2s.Sum256([]byte(str))
	return base36.EncodeBytes(h[:])
}

func (cache *LocalJWTCache) fileName(key string) string {
	return cache.hash(key) + ".jwt"
}

// A MemoryJWTCache stores JWTs in an in-memory map.
type MemoryJWTCache struct {
	mu      sync.Mutex
	entries map[string]string
}

// NewMemoryJWTCache creates a new in-memory JWT cache.
func NewMemoryJWTCache() *MemoryJWTCache {
	return &MemoryJWTCache{entries: make(map[string]string)}
}

// LoadJWT loads a JWT from the in-memory map.
func (cache *MemoryJWTCache) LoadJWT(key string) (rawJWT string, err error) {
	cache.mu.Lock()
	defer cache.mu.Unlock()

	rawJWT, ok := cache.entries[key]
	if !ok {
		return "", ErrNotFound
	}

	return rawJWT, checkExpiry(rawJWT)
}

// StoreJWT stores a JWT in the in-memory map.
func (cache *MemoryJWTCache) StoreJWT(key string, rawJWT string) error {
	cache.mu.Lock()
	defer cache.mu.Unlock()

	cache.entries[key] = rawJWT

	return nil
}

func checkExpiry(rawJWT string) error {
	tok, err := jose.ParseSigned(rawJWT)
	if err != nil {
		return ErrInvalid
	}

	var claims struct {
		Expiry int64 `json:"exp"`
	}
	err = json.Unmarshal(tok.UnsafePayloadWithoutVerification(), &claims)
	if err != nil {
		return ErrInvalid
	}

	expiresAt := time.Unix(claims.Expiry, 0)
	if expiresAt.Before(time.Now()) {
		return ErrExpired
	}

	return nil
}
