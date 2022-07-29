package sets

// A SizeLimited is a Set which is limited to a given size. Once
// the capacity is reached an element will be removed at random.
type SizeLimited[T comparable] struct {
	m        map[T]struct{}
	capacity int
}

// NewSizeLimited create a new SizeLimited.
func NewSizeLimited[T comparable](capacity int) *SizeLimited[T] {
	return &SizeLimited[T]{
		m:        make(map[T]struct{}),
		capacity: capacity,
	}
}

// Add adds an element to the set.
func (s *SizeLimited[T]) Add(element T) {
	s.m[element] = struct{}{}
	for len(s.m) > s.capacity {
		for k := range s.m {
			delete(s.m, k)
			break
		}
	}
}

// ForEach iterates over all the elements in the set.
func (s *SizeLimited[T]) ForEach(callback func(element T) bool) {
	for k := range s.m {
		if !callback(k) {
			return
		}
	}
}
