package raft

import (
	"fmt"
	"sync"

	"github.com/hashicorp/raft"
)

// NewStableStore creates a new raft stable store.
//
// Data is stored in in-memory maps.
func NewStableStore() raft.StableStore {
	return &stableStore{
		bytesLookup:  make(map[string][]byte),
		uint64Lookup: make(map[string]uint64),
	}
}

type stableStore struct {
	mu           sync.RWMutex
	bytesLookup  map[string][]byte
	uint64Lookup map[string]uint64
}

func (s *stableStore) Set(key []byte, val []byte) error {
	s.mu.Lock()
	s.bytesLookup[string(key)] = val
	s.mu.Unlock()
	return nil
}

func (s *stableStore) Get(key []byte) ([]byte, error) {
	s.mu.RLock()
	val, ok := s.bytesLookup[string(key)]
	s.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("not found")
	}
	return val, nil
}

func (s *stableStore) SetUint64(key []byte, val uint64) error {
	s.mu.Lock()
	s.uint64Lookup[string(key)] = val
	s.mu.Unlock()
	return nil
}

func (s *stableStore) GetUint64(key []byte) (uint64, error) {
	s.mu.RLock()
	val, ok := s.uint64Lookup[string(key)]
	s.mu.RUnlock()
	if !ok {
		return val, fmt.Errorf("not found")
	}
	return val, nil
}
