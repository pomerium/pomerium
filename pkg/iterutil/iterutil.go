// Package iterutil contains functions for working with iterators.
package iterutil

import (
	"iter"
)

type (
	Seq[E any]     = iter.Seq[E]
	Seq2[K, V any] = iter.Seq2[K, V]
)

// Filter filters an iterator to only those values for which include returns true.
func Filter[E any](seq Seq[E], include func(e E) bool) Seq[E] {
	return func(yield func(E) bool) {
		for e := range seq {
			if !include(e) {
				continue
			}
			if !yield(e) {
				return
			}
		}
	}
}

// Keys returns the keys of an iterator over keys and values.
func Keys[K, V any](seq Seq2[K, V]) Seq[K] {
	return func(yield func(K) bool) {
		for k := range seq {
			if !yield(k) {
				return
			}
		}
	}
}

// Repeat endlessly repeats an element as an iterator.
func Repeat[E any](e E) Seq[E] {
	return func(yield func(E) bool) {
		for yield(e) {
		}
	}
}

// SkipLast skips the last n elements of an iterator.
func SkipLast[E any](seq Seq[E], n int) Seq[E] {
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

// SortedIntersection computes the set-intersection of zero or more sorted iterators.
// For an element to be returned, it must be found in all of the sequences. Values are
// assumed to be sorted. If they are not sorted the intersection will not be valid.
func SortedIntersection[E any](compare func(a, b E) int, seqs ...Seq[E]) Seq[E] {
	seqsWithError := make([]Seq2[E, error], len(seqs))
	for i, seq := range seqs {
		seqsWithError[i] = Zip(seq, Repeat(error(nil)))
	}
	return Keys(SortedIntersectionWithError(compare, seqsWithError...))
}

// SortedUnion computes the set-union of zero or more sorted iterators.
// For an element to be returned, it must be found in at least one of the sequences.
// Values are assumed to be sorted and only duplicates are removed.
func SortedUnion[E any](compare func(a, b E) int, seqs ...Seq[E]) Seq[E] {
	seqsWithError := make([]Seq2[E, error], len(seqs))
	for i, seq := range seqs {
		seqsWithError[i] = Zip(seq, Repeat(error(nil)))
	}
	return Keys(SortedUnionWithError(compare, seqsWithError...))
}

// Take returns the first n elements of an iterator.
func Take[E any](seq Seq[E], n int) Seq[E] {
	return func(yield func(E) bool) {
		i := 0
		for e := range seq {
			if i >= n {
				break
			}
			if !yield(e) {
				return
			}
			i++
		}
	}
}

// Zip combines two iterators. The combined iterator will stop when either iterator stops.
func Zip[K, V any](seqK Seq[K], seqV Seq[V]) Seq2[K, V] {
	return func(yield func(K, V) bool) {
		nextK, stopK := iter.Pull(seqK)
		defer stopK()
		nextV, stopV := iter.Pull(seqV)
		defer stopV()

		for {
			k, ok := nextK()
			if !ok {
				break
			}
			v, ok := nextV()
			if !ok {
				break
			}
			if !yield(k, v) {
				return
			}
		}
	}
}
