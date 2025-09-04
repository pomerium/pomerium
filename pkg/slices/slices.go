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

// Map constructs a new slice containing the elements obtained by invoking the
// function f on each element of s.
func Map[S ~[]E, E, T any](s S, f func(E) T) []T {
	ns := make([]T, len(s))
	for i := range s {
		ns[i] = f(s[i])
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

// Reverse reverses a slice's order.
func Reverse[S ~[]E, E comparable](s S) {
	for i := 0; i < len(s)/2; i++ {
		s[i], s[len(s)-1-i] = s[len(s)-1-i], s[i]
	}
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

// UniqueBy returns the unique elements of s using a function to map elements.
func UniqueBy[S ~[]E, E any, V comparable](s S, by func(E) V) S {
	var ns S
	h := map[V]struct{}{}
	for _, el := range s {
		v := by(el)
		if _, ok := h[v]; !ok {
			h[v] = struct{}{}
			ns = append(ns, el)
		}
	}
	return ns
}

// Difference returns the difference between two collections.
// The first value is the collection of element absent of list2.
// The second value is the collection of element absent of list1.
func Difference[T comparable, Slice ~[]T](list1 Slice, list2 Slice) (Slice, Slice) {
	left := Slice{}
	right := Slice{}

	seenLeft := map[T]struct{}{}
	seenRight := map[T]struct{}{}

	for i := range list1 {
		seenLeft[list1[i]] = struct{}{}
	}

	for i := range list2 {
		seenRight[list2[i]] = struct{}{}
	}

	for i := range list1 {
		if _, ok := seenRight[list1[i]]; !ok {
			left = append(left, list1[i])
		}
	}

	for i := range list2 {
		if _, ok := seenLeft[list2[i]]; !ok {
			right = append(right, list2[i])
		}
	}

	return left, right
}
