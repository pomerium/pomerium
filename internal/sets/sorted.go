package sets

import "github.com/google/btree"

type stringItem string

func (item stringItem) Less(than btree.Item) bool {
	return item < than.(stringItem)
}

// A SortedString is a set of strings with sorted iteration.
type SortedString struct {
	b *btree.BTree
}

// NewSortedString creates a new sorted string set.
func NewSortedString() *SortedString {
	return &SortedString{
		b: btree.New(8),
	}
}

// Add adds a string to the set.
func (s *SortedString) Add(elements ...string) {
	for _, element := range elements {
		s.b.ReplaceOrInsert(stringItem(element))
	}
}

// Clear clears the set.
func (s *SortedString) Clear() {
	s.b = btree.New(8)
}

// Delete deletes an element from the set.
func (s *SortedString) Delete(element string) {
	s.b.Delete(stringItem(element))
}

// ForEach iterates over the set in ascending order.
func (s *SortedString) ForEach(callback func(element string) bool) {
	s.b.Ascend(func(i btree.Item) bool {
		return callback(string(i.(stringItem)))
	})
}

// Has returns true if the elment is in the set.
func (s *SortedString) Has(element string) bool {
	return s.b.Has(stringItem(element))
}

// Size returns the size of the set.
func (s *SortedString) Size() int {
	return s.b.Len()
}

// ToSlice returns a slice of all the elements in the set.
func (s *SortedString) ToSlice() []string {
	arr := make([]string, 0, s.Size())
	s.b.Ascend(func(i btree.Item) bool {
		arr = append(arr, string(i.(stringItem)))
		return true
	})
	return arr
}
