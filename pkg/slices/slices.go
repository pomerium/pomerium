// Package slices contains functions for working with slices.
package slices

// Contains returns true if e is in s.
func Contains[S ~[]E, E comparable](s S, e E) bool {
	for _, el := range s {
		if el == e {
			return true
		}
	}
	return false
}

// Filter returns a new slice containing only those elements for which f(element) is true.
func Filter[S ~[]E, E any](s S, f func(E) bool) S {
	var ns S
	for _, el := range s {
		if f(el) {
			ns = append(ns, el)
		}
	}
	return ns
}

// Remove removes e from s.
func Remove[S ~[]E, E comparable](s S, e E) S {
	var ns S
	for _, el := range s {
		if el != e {
			ns = append(ns, el)
		}
	}
	return ns
}

// Unique returns the unique elements of s.
func Unique[S ~[]E, E comparable](s S) S {
	var ns S
	h := map[E]struct{}{}
	for _, el := range s {
		if _, ok := h[el]; !ok {
			h[el] = struct{}{}
			ns = append(ns, el)
		}
	}
	return ns
}
