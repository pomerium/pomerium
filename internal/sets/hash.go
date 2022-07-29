package sets

// A Hash is a set implemented via a map.
type Hash[T comparable] struct {
	m map[T]struct{}
}

// NewHash creates a new Hash set.
func NewHash[T comparable](initialValues ...T) *Hash[T] {
	s := &Hash[T]{
		m: make(map[T]struct{}),
	}
	s.Add(initialValues...)
	return s
}

// Add adds a value to the set.
func (s *Hash[T]) Add(elements ...T) {
	for _, element := range elements {
		s.m[element] = struct{}{}
	}
}

// Has returns true if the element is in the set.
func (s *Hash[T]) Has(element T) bool {
	_, ok := s.m[element]
	return ok
}

// Size returns the size of the set.
func (s *Hash[T]) Size() int {
	return len(s.m)
}
