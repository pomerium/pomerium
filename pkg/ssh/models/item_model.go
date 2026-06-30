package models

import (
	"fmt"
	"iter"
	"slices"
	"sync"
)

//go:generate go tool go.uber.org/mock/mockgen -typed -destination ./mock/mock_item_model.go . ItemModelListener

type Index int

func (i Index) IsValid(model interface{ End() Index }) bool {
	return i >= 0 && i < model.End()
}

func (i Index) isValidLocked(model interface{ endLocked() Index }) bool {
	return i >= 0 && i < model.endLocked()
}

type Item[K comparable] interface {
	Key() K
	ToRow() []string
}

type ItemModel[T Item[K], K comparable] interface {
	Index(key K) Index
	Find(key K) T
	Data(Index) T
	Put(T)
	Delete(Index)
	Reset(items []T)
	End() Index
	AddListener(l ItemModelListener[T, K])
	RemoveListener(l ItemModelListener[T, K])
	Listeners() iter.Seq[ItemModelListener[T, K]]
	InvalidateAll()
}

type itemModel[T Item[K], K comparable] struct {
	items       []T
	indexLookup map[K]Index
	listeners   []ItemModelListener[T, K]
	mu          sync.Mutex
}

type IndexUpdateMsg[T Item[K], K comparable] struct {
	Begin, End Index
	Items      []T
}

type ModelResetMsg[T Item[K], K comparable] struct {
	Items []T
}

type ItemModelListener[T Item[K], K comparable] interface {
	OnIndexUpdate(begin Index, end Index, items []T)
	OnModelReset(items []T)
}

func NewItemModel[T Item[K], K comparable]() ItemModel[T, K] {
	return &itemModel[T, K]{
		indexLookup: map[K]Index{},
	}
}

func (m *itemModel[T, K]) Index(key K) Index {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.indexLocked(key)
}

func (m *itemModel[T, K]) indexLocked(key K) Index {
	idx, ok := m.indexLookup[key]
	if !ok {
		return m.endLocked()
	}
	return idx
}

func (m *itemModel[T, K]) Find(key K) (_ T) {
	m.mu.Lock()
	defer m.mu.Unlock()
	idx := m.indexLocked(key)
	if !idx.isValidLocked(m) {
		return
	}
	return m.items[idx]
}

func (m *itemModel[T, K]) Data(idx Index) T {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.items[idx]
}

func (m *itemModel[T, K]) Put(item T) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := item.Key()
	idx := m.indexLocked(key)
	if idx.isValidLocked(m) {
		// update
		m.items[idx] = item
		m.notifyListenersLocked(idx, idx+1, item)
	} else {
		// append
		m.items = append(m.items, item)
		m.indexLookup[key] = idx
		m.notifyListenersLocked(idx, idx, item)
	}
}

func (m *itemModel[T, K]) notifyListenersLocked(begin, end Index, items ...T) {
	for _, l := range m.listeners {
		l.OnIndexUpdate(begin, end, items)
	}
}

func (m *itemModel[T, K]) Delete(idx Index) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !idx.isValidLocked(m) {
		panic(fmt.Sprintf("bug: Delete called with invalid model index %d", idx))
	}
	prevEnd := m.endLocked()
	deleted := m.items[idx]
	delete(m.indexLookup, deleted.Key())
	m.items = slices.Delete(m.items, int(idx), int(idx+1))
	// shift indexes of items after the deleted one
	for i := int(idx); i < len(m.items); i++ {
		m.indexLookup[m.items[i].Key()]--
	}

	m.notifyListenersLocked(idx, prevEnd, slices.Clone(m.items[idx:m.endLocked()])...)
}

func (m *itemModel[T, K]) Reset(items []T) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.items = items
	clear(m.indexLookup)
	for i, item := range m.items {
		m.indexLookup[item.Key()] = Index(i)
	}
	for _, l := range m.listeners {
		l.OnModelReset(slices.Clone(m.items))
	}
}

func (m *itemModel[T, K]) End() Index {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.endLocked()
}

func (m *itemModel[T, K]) endLocked() Index {
	return Index(len(m.items))
}

func (m *itemModel[T, K]) InvalidateAll() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, l := range m.listeners {
		l.OnModelReset(slices.Clone(m.items))
	}
}

func (m *itemModel[T, K]) AddListener(l ItemModelListener[T, K]) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.items) > 0 {
		l.OnIndexUpdate(Index(0), Index(0), slices.Clone(m.items))
	}
	m.listeners = append(m.listeners, l)
}

func (m *itemModel[T, K]) RemoveListener(l ItemModelListener[T, K]) {
	m.mu.Lock()
	defer m.mu.Unlock()
	idx := slices.Index(m.listeners, l)
	m.listeners = slices.Delete(m.listeners, idx, idx+1)
}

func (m *itemModel[T, K]) Listeners() iter.Seq[ItemModelListener[T, K]] {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Values(m.listeners)
}
