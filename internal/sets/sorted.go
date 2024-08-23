package sets

import (
	"iter"

	"github.com/google/btree"
	"golang.org/x/exp/constraints"
)

// A Sorted is a set with sorted iteration.
type Sorted[T any] struct {
	b    *btree.BTreeG[T]
	less func(a, b T) bool
}

// NewSorted creates a new sorted string set.
func NewSorted[T constraints.Ordered]() *Sorted[T] {
	less := func(a, b T) bool {
		return a < b
	}
	return &Sorted[T]{
		b:    btree.NewG(8, less),
		less: less,
	}
}

// Add adds a string to the set.
func (s *Sorted[T]) Add(elements ...T) {
	for _, element := range elements {
		s.b.ReplaceOrInsert(element)
	}
}

// Clear clears the set.
func (s *Sorted[T]) Clear() {
	s.b = btree.NewG(8, s.less)
}

// Delete deletes an element from the set.
func (s *Sorted[T]) Delete(element T) {
	s.b.Delete(element)
}

// ForEach iterates over the set in ascending order.
func (s *Sorted[T]) ForEach(callback func(element T) bool) {
	s.b.Ascend(func(item T) bool {
		return callback(item)
	})
}

// Has returns true if the element is in the set.
func (s *Sorted[T]) Has(element T) bool {
	return s.b.Has(element)
}

// Size returns the size of the set.
func (s *Sorted[T]) Size() int {
	return s.b.Len()
}

// ToSlice returns a slice of all the elements in the set.
func (s *Sorted[T]) ToSlice() []T {
	arr := make([]T, 0, s.Size())
	s.b.Ascend(func(item T) bool {
		arr = append(arr, item)
		return true
	})
	return arr
}

func (s *Sorted[T]) All() iter.Seq[T] {
	return func(yield func(T) bool) {
		s.b.Ascend(yield)
	}
}
