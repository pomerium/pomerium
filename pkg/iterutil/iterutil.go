// Package iterutil contains functions for working with iterators.
package iterutil

import "iter"

// CollectWithError takes a sequence of values and errors and turns it
// into a slice or error.
func CollectWithError[E any](seq iter.Seq2[E, error]) ([]E, error) {
	var s []E
	for e, err := range seq {
		if err != nil {
			return nil, err
		}
		s = append(s, e)
	}
	return s, nil
}

// SkipLast skips the last n elements of an iterator.
func SkipLast[E any](seq iter.Seq[E], n int) iter.Seq[E] {
	if n <= 0 {
		return seq
	}
	return func(yield func(E) bool) {
		buf := make([]E, n)
		idx := 0
		for e := range seq {
			if idx >= n && !yield(buf[idx%n]) {
				return
			}
			buf[idx%n] = e
			idx++
		}
	}
}

func SkipLast2[K, V any](seq iter.Seq2[K, V], n int) iter.Seq2[K, V] {
	if n <= 0 {
		return seq
	}
	return func(yield func(K, V) bool) {
		ks, vs := make([]K, n), make([]V, n)
		idx := 0
		for k, v := range seq {
			if idx >= n && !yield(ks[idx%n], vs[idx%n]) {
				return
			}
			ks[idx%n] = k
			vs[idx%n] = v
			idx++
		}
	}
}
