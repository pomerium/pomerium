package sets

// A SizeLimitedStringSet is a StringSet which is limited to a given size. Once
// the capacity is reached an element will be removed at random.
type SizeLimitedStringSet struct {
	m        map[string]struct{}
	capacity int
}

// NewSizeLimitedStringSet create a new SizeLimitedStringSet.
func NewSizeLimitedStringSet(capacity int) *SizeLimitedStringSet {
	return &SizeLimitedStringSet{
		m:        make(map[string]struct{}),
		capacity: capacity,
	}
}

// Add adds an element to the set.
func (s *SizeLimitedStringSet) Add(element string) {
	s.m[element] = struct{}{}
	for len(s.m) > s.capacity {
		for k := range s.m {
			delete(s.m, k)
			break
		}
	}
}

// ForEach iterates over all the elements in the set.
func (s *SizeLimitedStringSet) ForEach(callback func(element string) bool) {
	for k := range s.m {
		if !callback(k) {
			return
		}
	}
}
