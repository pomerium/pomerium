package raft

import (
	"cmp"
	"sync"

	"github.com/google/btree"
	"github.com/hashicorp/raft"
)

const btreeDegree int = 16

// NewLogStore creates a new raft log store.
//
// Logs are stored in a btree ordered by index.
func NewLogStore() raft.LogStore {
	return &logStore{
		logs: btree.NewG(btreeDegree, func(log1, log2 *raft.Log) bool {
			return cmp.Compare(log1.Index, log2.Index) < 0
		}),
	}
}

type logStore struct {
	mu   sync.RWMutex
	logs *btree.BTreeG[*raft.Log]
}

func (s *logStore) FirstIndex() (uint64, error) {
	s.mu.RLock()
	log, ok := s.logs.Min()
	s.mu.RUnlock()
	if !ok {
		return 0, nil
	}
	return log.Index, nil
}

func (s *logStore) LastIndex() (uint64, error) {
	s.mu.RLock()
	log, ok := s.logs.Max()
	s.mu.RUnlock()
	if !ok {
		return 0, nil
	}
	return log.Index, nil
}

func (s *logStore) GetLog(index uint64, log *raft.Log) error {
	s.mu.RLock()
	l, ok := s.logs.Get(&raft.Log{Index: index})
	s.mu.RUnlock()
	if !ok {
		return raft.ErrLogNotFound
	}
	*log = *l
	return nil
}

func (s *logStore) StoreLog(log *raft.Log) error {
	s.mu.Lock()
	s.logs.ReplaceOrInsert(log)
	s.mu.Unlock()
	return nil
}

func (s *logStore) StoreLogs(logs []*raft.Log) error {
	s.mu.Lock()
	for _, log := range logs {
		s.logs.ReplaceOrInsert(log)
	}
	s.mu.Unlock()
	return nil
}

func (s *logStore) DeleteRange(minIndex, maxIndex uint64) error {
	s.mu.Lock()
	for i := minIndex; i <= maxIndex; i++ {
		_, _ = s.logs.Delete(&raft.Log{Index: i})
	}
	s.mu.Unlock()
	return nil
}
