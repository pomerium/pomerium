package model

import (
	"fmt"
	"iter"
	"slices"
)

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
	Find(key K) (Index, T)
	Insert(Index, T)
	Delete(Index)
	Replace(begin, end Index, items []T)
	End() Index
	AddListener(l ItemModelListener[T, K])
	RemoveListener(l ItemModelListener[T, K])
	Listeners() iter.Seq[ItemModelListener[T, K]]
	InvalidateAll()
}

type ItemModelImpl[T Item[K], K comparable] struct {
	items       []T
	indexLookup map[K]Index
	listeners   []ItemModelListener[T, K]
}

type ItemModelListener[T Item[K], K comparable] interface {
	OnIndexUpdate(begin, end Index, items []T)
}

func NewItemModel[T Item[K], K comparable]() ItemModel[T, K] {
	return &ItemModelImpl[T, K]{
		indexLookup: map[K]Index{},
	}
}

func (m *ItemModelImpl[T, K]) Index(key K) Index {
	idx, ok := m.indexLookup[key]
	if !ok {
		return m.End()
	}
	return idx
}

func (m *ItemModelImpl[T, K]) Find(key K) (idx Index, _ T) {
	idx = m.Index(key)
	if !idx.IsValid(m) {
		return
	}
	return idx, m.items[idx]
}

func (m *ItemModelImpl[T, K]) Insert(idx Index, item T) {
	var begin, end Index
	if idx == m.End() {
		key := item.Key()
		m.items = append(m.items, item)
		m.indexLookup[key] = idx
		begin = idx
		end = idx
	} else if idx.IsValid(m) {
		m.items[idx] = item
		begin = idx
		end = idx + 1
	} else {
		panic(fmt.Sprintf("bug: Insert called with invalid model index %d", idx))
	}
	for _, l := range m.listeners {
		l.OnIndexUpdate(begin, end, []T{item})
	}
}

func (m *ItemModelImpl[T, K]) Delete(idx Index) {
	if !idx.IsValid(m) {
		panic(fmt.Sprintf("bug: Delete called with invalid model index %d", idx))
	}
	prevEnd := m.End()
	m.items = slices.Delete(m.items, int(idx), int(idx+1))
	for _, l := range m.listeners {
		l.OnIndexUpdate(idx, prevEnd, m.items[idx:m.End()])
	}
}

func (m *ItemModelImpl[T, K]) Replace(begin, end Index, items []T) {
	if (begin != end && !begin.IsValid(m)) || end < begin || end > m.End() {
		panic(fmt.Sprintf("bug: Delete called with invalid range [%d,%d)", begin, end))
	}
	prevEnd := m.End()
	prevLen := len(m.items)
	m.items = slices.Replace(m.items, int(begin), int(end), items...)

	if len(m.items) == prevLen {
		// size has not changed
		for _, l := range m.listeners {
			l.OnIndexUpdate(begin, end, m.items[begin:end])
		}
	} else {
		// if rows were added/removed, invalidate all indexes after begin
		for _, l := range m.listeners {
			l.OnIndexUpdate(begin, prevEnd, m.items[begin:m.End()])
		}
	}
}

func (m *ItemModelImpl[T, K]) End() Index {
	return Index(len(m.items))
}

func (m *ItemModelImpl[T, K]) InvalidateAll() {
	for _, l := range m.listeners {
		l.OnIndexUpdate(0, m.End(), m.items)
	}
}

func (m *ItemModelImpl[T, K]) AddListener(l ItemModelListener[T, K]) {
	l.OnIndexUpdate(Index(0), Index(0), m.items)
	m.listeners = append(m.listeners, l)
}

func (m *ItemModelImpl[T, K]) RemoveListener(l ItemModelListener[T, K]) {
	idx := slices.Index(m.listeners, l)
	m.listeners = slices.Delete(m.listeners, idx, idx+1)
}

func (m *ItemModelImpl[T, K]) Listeners() iter.Seq[ItemModelListener[T, K]] {
	return slices.Values(m.listeners)
}
