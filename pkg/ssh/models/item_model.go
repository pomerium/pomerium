package models

import (
	"fmt"
	"iter"
	"slices"
)

//go:generate go tool -modfile ../../../internal/tools/go.mod go.uber.org/mock/mockgen -typed -destination ./mock/mock_item_model.go . ItemModelListener

type Index int

func (i Index) IsValid(model interface{ End() Index }) bool {
	return i >= 0 && i < model.End()
}

type IndexUpdateMsg[T Item[K], K comparable] struct {
	Item  T
	Index Index
}

type Item[K comparable] interface {
	Key() K
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
	idx, ok := m.indexLookup[key]
	if !ok {
		return m.End()
	}
	return idx
}

func (m *itemModel[T, K]) Find(key K) (_ T) {
	idx := m.Index(key)
	if !idx.IsValid(m) {
		return
	}
	return m.items[idx]
}

func (m *itemModel[T, K]) Data(idx Index) T {
	return m.items[idx]
}

func (m *itemModel[T, K]) Put(item T) {
	key := item.Key()
	idx := m.Index(key)
	if idx.IsValid(m) {
		// update
		m.items[idx] = item
		m.notifyListeners(idx, idx+1, item)
	} else {
		// append
		m.items = append(m.items, item)
		m.indexLookup[key] = idx
		m.notifyListeners(idx, idx, item)
	}
}

func (m *itemModel[T, K]) notifyListeners(begin, end Index, items ...T) {
	for _, l := range m.listeners {
		l.OnIndexUpdate(begin, end, items)
	}
}

func (m *itemModel[T, K]) Delete(idx Index) {
	if !idx.IsValid(m) {
		panic(fmt.Sprintf("bug: Delete called with invalid model index %d", idx))
	}
	prevEnd := m.End()
	deleted := m.items[idx]
	delete(m.indexLookup, deleted.Key())
	m.items = slices.Delete(m.items, int(idx), int(idx+1))
	// shift indexes of items after the deleted one
	for i := int(idx); i < len(m.items); i++ {
		m.indexLookup[m.items[i].Key()]--
	}

	m.notifyListeners(idx, prevEnd, m.items[idx:m.End()]...)
}

func (m *itemModel[T, K]) Reset(items []T) {
	m.items = items
	clear(m.indexLookup)
	for i, item := range m.items {
		m.indexLookup[item.Key()] = Index(i)
	}
	for _, l := range m.listeners {
		l.OnModelReset(m.items)
	}
}

func (m *itemModel[T, K]) End() Index {
	return Index(len(m.items))
}

func (m *itemModel[T, K]) InvalidateAll() {
	for _, l := range m.listeners {
		l.OnModelReset(m.items)
	}
}

func (m *itemModel[T, K]) AddListener(l ItemModelListener[T, K]) {
	if len(m.items) > 0 {
		l.OnIndexUpdate(Index(0), Index(0), m.items)
	}
	m.listeners = append(m.listeners, l)
}

func (m *itemModel[T, K]) RemoveListener(l ItemModelListener[T, K]) {
	idx := slices.Index(m.listeners, l)
	m.listeners = slices.Delete(m.listeners, idx, idx+1)
}

func (m *itemModel[T, K]) Listeners() iter.Seq[ItemModelListener[T, K]] {
	return slices.Values(m.listeners)
}
