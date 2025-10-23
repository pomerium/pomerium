package storage

import (
	"hash/fnv"
	"slices"
	"sync"
	"sync/atomic"
)

type indexer interface {
	Put(secondaryKey string, recordID string)
	Delete(secondaryKey string, recordID string)
	List(secondaryKey string) (recordIds []string)
}

type naiveIndexer struct {
	contentMu sync.Mutex
	contents  map[string][]string
}

func newIndexer() *naiveIndexer {
	return &naiveIndexer{
		contentMu: sync.Mutex{},
		contents:  map[string][]string{},
	}
}

var _ indexer = (*naiveIndexer)(nil)

func (i *naiveIndexer) Put(secondaryKey string, recordID string) {
	i.contentMu.Lock()
	defer i.contentMu.Unlock()
	val, ok := i.contents[secondaryKey]
	if !ok {
		i.contents[secondaryKey] = []string{}
	}
	i.contents[secondaryKey] = slices.DeleteFunc(val, func(v string) bool {
		return v == recordID
	})
	i.contents[secondaryKey] = append(i.contents[secondaryKey], recordID)
}

func (i *naiveIndexer) Delete(secondaryKey string, recordID string) {
	i.contentMu.Lock()
	defer i.contentMu.Unlock()

	val, ok := i.contents[secondaryKey]
	if !ok {
		return
	}
	i.contents[secondaryKey] = slices.DeleteFunc(val, func(v string) bool {
		return v == recordID
	})

	if len(i.contents[secondaryKey]) == 0 {
		delete(i.contents, secondaryKey)
	}

}

func (i *naiveIndexer) List(secondaryKey string) (recordIds []string) {
	i.contentMu.Lock()
	defer i.contentMu.Unlock()
	val, ok := i.contents[secondaryKey]
	if !ok {
		return []string{}
	}
	return val
}

type fastIndexer struct {
	shards []sync.Map
	n      uint32
}

func NewFastIndexer(numShards uint32) *fastIndexer {
	shards := make([]sync.Map, numShards)
	for i := range numShards {
		shards[i] = sync.Map{}
	}
	return &fastIndexer{
		shards: shards,
		n:      numShards,
	}
}

var _ indexer = (*fastIndexer)(nil)

func (f *fastIndexer) Put(secondaryKey string, recordID string) {
	f.add(secondaryKey, recordID)
}

func (f *fastIndexer) List(secondaryKey string) (recordIDs []string) {
	return f.get(secondaryKey)
}

func (f *fastIndexer) Delete(secondaryKey string, recordID string) {
	f.delete(secondaryKey, recordID)
}

func (f *fastIndexer) shardFor(key string) *sync.Map {
	h := fnv.New32()
	_, _ = h.Write([]byte(key))
	return &f.shards[h.Sum32()%f.n]
}

func (f *fastIndexer) add(key, val string) {
	sh := f.shardFor(key)
	v, _ := sh.LoadOrStore(key, &atomic.Pointer[map[string]struct{}]{})
	ptr := v.(*atomic.Pointer[map[string]struct{}])
	for {
		old := ptr.Load()
		newSet := make(map[string]struct{})
		for k := range *old {
			newSet[k] = struct{}{}
		}
		newSet[val] = struct{}{}
		if ptr.CompareAndSwap(old, &newSet) {
			break
		}
	}
}

func (f *fastIndexer) delete(key, val string) {
	sh := f.shardFor(key)
	v, _ := sh.LoadOrStore(key, &atomic.Pointer[map[string]struct{}]{})
	ptr := v.(*atomic.Pointer[map[string]struct{}])
	for {
		old := ptr.Load()
		newSet := make(map[string]struct{})
		for k := range *old {
			newSet[k] = struct{}{}
		}
		delete(newSet, val)
		if ptr.CompareAndSwap(old, &newSet) {
			break
		}
	}
}

func (f *fastIndexer) get(key string) []string {
	sh := f.shardFor(key)
	v, ok := sh.Load(key)
	if !ok {
		return []string{}
	}
	ptr := v.(*atomic.Pointer[map[string]struct{}])
	got := ptr.Load()
	ret := make([]string, len(*got))
	idx := 0
	for k := range *got {
		ret[idx] = k
		idx += 1
	}
	return ret
}
