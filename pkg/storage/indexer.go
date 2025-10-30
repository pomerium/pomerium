package storage

import (
	"fmt"
	"hash/fnv"
	"iter"
	"maps"
	"slices"
	"strings"
	"sync"
	"sync/atomic"

	"google.golang.org/protobuf/types/known/anypb"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	slicesutil "github.com/pomerium/pomerium/pkg/slices"
)

type Indexer interface {
	Put(secondaryKey string, recordID string)
	Delete(secondaryKey string, recordID string)
	List(secondaryKey string) (recordIDs []string)
}

type simpleindexer struct {
	contentMu sync.Mutex
	contents  map[string][]string
}

// NewSimpleIndexer implements an index that maps on set of keys
// to multiple keys. It is an in-memory datastructure that is thread-safe,
// but each of its operations is locked behind a mutex.
func NewSimpleIndexer() Indexer {
	return &simpleindexer{
		contentMu: sync.Mutex{},
		contents:  map[string][]string{},
	}
}

var _ Indexer = (*simpleindexer)(nil)

func (i *simpleindexer) Put(secondaryKey string, recordID string) {
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

func (i *simpleindexer) Delete(secondaryKey string, recordID string) {
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

func (i *simpleindexer) List(secondaryKey string) (recordIDs []string) {
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

// NewFastIndexer creates a lock-free datastructure
// for mapping one set of keys to multiple sets of keys.
// Importantly, the lock free nature reduces hot-path contention for singular
// operations; but it relies on deep copy semantics to achieve this -
// an index with a large amount of keys with many concurrent updates
// will perform extremely poorly, but a large set of indexes that map
// to a small amount of values will perform well under any set of
// conditions
func NewFastIndexer(numShards uint32) Indexer {
	shards := make([]sync.Map, numShards)
	for i := range numShards {
		shards[i] = sync.Map{}
	}
	return &fastIndexer{
		shards: shards,
		n:      numShards,
	}
}

var _ Indexer = (*fastIndexer)(nil)

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
		for k := range iterFromMapPtr(old) {
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
		for k := range iterFromMapPtr(old) {
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
	for k := range iterFromMapPtr(got) {
		ret[idx] = k
		idx++
	}
	return ret
}

func iterFromMapPtr(ptr *map[string]struct{}) iter.Seq[string] {
	if ptr == nil {
		return func(_ func(string) bool) {}
	}
	return maps.Keys(*ptr)
}

type IndexManager struct {
	indexMu        *sync.RWMutex
	genericIndices map[string]Indexer
	fields         []string

	indexFactory func() Indexer
}

func NewIndexManager(
	indexFactory func() Indexer,
) *IndexManager {
	return &IndexManager{
		indexMu:        &sync.RWMutex{},
		genericIndices: map[string]Indexer{},
		fields:         []string{},
		indexFactory:   indexFactory,
	}
}

func (i *IndexManager) Clear() {
	i.indexMu.Lock()
	defer i.indexMu.Unlock()
	freshIndices := map[string]Indexer{}
	for idx := range i.genericIndices {
		freshIndices[idx] = i.indexFactory()
	}
	i.genericIndices = freshIndices
}

func (i *IndexManager) SetIndexableFields(fields []string, recordsF func() []*databroker.Record) {
	i.indexMu.Lock()
	defer i.indexMu.Unlock()
	i.compareAndReindex(fields, recordsF)
}

func (i *IndexManager) compareAndReindex(incomingFields []string, recordsF func() []*databroker.Record) {
	previousFields := i.fields
	toDelete, toAdd := slicesutil.Difference(previousFields, incomingFields)

	for _, keypath := range toDelete {
		delete(i.genericIndices, keypath)
	}

	for _, newMapping := range toAdd {
		i.genericIndices[newMapping] = i.indexFactory()
	}

	records := recordsF()
	for _, record := range records {
		fields, err := GetIndexableFields(record.GetData(), toAdd)
		if err != nil {
			return
		}
		for mKey, mVal := range fields {
			if mVal == "" {
				continue
			}
			_, ok := i.genericIndices[mKey]
			if !ok {
				panic(fmt.Sprintf("expected mapping : %s", mKey))
			}
			i.genericIndices[mKey].Put(mVal, record.GetId())
		}
	}
	i.fields = incomingFields
}

func (i *IndexManager) GetRelatedIDs(expr EqualsFilterExpression) ([]string, error) {
	keyPath := strings.Join(expr.Fields, ".")
	i.indexMu.RLock()
	idxer, ok := i.genericIndices[keyPath]
	i.indexMu.RUnlock()
	if !ok {
		return nil, ErrNoSuchIndex
	}
	return idxer.List(expr.Value), nil
}

func (i *IndexManager) Update(recordID string, msg *anypb.Any) {
	i.indexMu.RLock()
	flds := i.fields
	i.indexMu.RUnlock()
	if len(flds) == 0 {
		return
	}
	fields, err := GetIndexableFields(msg, flds)
	if err != nil {
		return
	}
	for mKey, mVal := range fields {
		if mVal == "" {
			continue
		}
		i.addIndexableField(mKey, mVal, recordID)
	}
}

func (i *IndexManager) removeIndexableField(keyName, keyValue, recordID string) {
	i.indexMu.RLock()
	_, ok := i.genericIndices[keyName]
	i.indexMu.RUnlock()
	if !ok {
		return
	}
	i.genericIndices[keyName].Delete(keyValue, recordID)
}

func (i *IndexManager) addIndexableField(keyName, keyValue, recordID string) {
	i.indexMu.RLock()
	_, ok := i.genericIndices[keyName]
	i.indexMu.RUnlock()
	if !ok {
		return
	}
	i.genericIndices[keyName].Put(keyValue, recordID)
}

func (i *IndexManager) Delete(recordID string, msg *anypb.Any) {
	i.indexMu.RLock()
	flds := i.fields
	i.indexMu.RUnlock()
	if len(flds) == 0 {
		return
	}
	fields, err := GetIndexableFields(msg, flds)
	if err != nil {
		return
	}
	for mKey, mVal := range fields {
		if mVal == "" {
			continue
		}
		i.removeIndexableField(mKey, mVal, recordID)
	}
}
