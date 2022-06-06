package sets

import "github.com/google/btree"

func lessFn(a, b string) bool { return a < b }

// A SortedString is a set of strings with sorted iteration.
type SortedString struct {
	b *btree.BTreeG[string]
}

// NewSortedString creates a new sorted string set.
func NewSortedString() *SortedString {
	return &SortedString{
		b: btree.NewG[string](8, lessFn),
	}
}

// Add adds a string to the set.
func (s *SortedString) Add(elements ...string) {
	for _, element := range elements {
		s.b.ReplaceOrInsert(element)
	}
}

// Clear clears the set.
func (s *SortedString) Clear() {
	s.b = btree.NewG[string](8, lessFn)
}

// Delete deletes an element from the set.
func (s *SortedString) Delete(element string) {
	s.b.Delete(element)
}

// ForEach iterates over the set in ascending order.
func (s *SortedString) ForEach(callback func(element string) bool) {
	s.b.Ascend(func(item string) bool {
		return callback(item)
	})
}

// Has returns true if the elment is in the set.
func (s *SortedString) Has(element string) bool {
	return s.b.Has(element)
}

// Size returns the size of the set.
func (s *SortedString) Size() int {
	return s.b.Len()
}

// ToSlice returns a slice of all the elements in the set.
func (s *SortedString) ToSlice() []string {
	arr := make([]string, 0, s.Size())
	s.b.Ascend(func(item string) bool {
		arr = append(arr, item)
		return true
	})
	return arr
}
