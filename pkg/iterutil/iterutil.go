// Package iterutil contains functions for working with iterators.
package iterutil

import (
	"iter"

	"golang.org/x/exp/constraints"
)

// Chunk returns an iterator over consecutive sub-slices of up to n elements of seq.
// All but the last sub-slice will have size n.
func Chunk[E any](seq iter.Seq[E], n int) iter.Seq[[]E] {
	return func(yield func([]E) bool) {
		buf := make([]E, 0, n)
		for e := range seq {
			buf = append(buf, e)
			if len(buf) == n {
				if !yield(buf) {
					return
				}
				buf = buf[:0]
			}
		}
		// the last chunk may have less than n elements
		if len(buf) > 0 {
			yield(buf)
		}
	}
}

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

func Count[E constraints.Integer](start E) iter.Seq[E] {
	return func(yield func(E) bool) {
		for i := start; ; i++ {
			if !yield(i) {
				return
			}
		}
	}
}

// Filter filters an iterator to only those values for which include returns true.
func Filter[E any](seq iter.Seq[E], include func(e E) bool) iter.Seq[E] {
	return func(yield func(E) bool) {
		for e := range seq {
			if include(e) && !yield(e) {
				return
			}
		}
	}
}

// FilterWithError filters an iterator to only those values for which include returns true.
//
// If any error occurs in any iterator it will be returned and stop.
func FilterWithError[E any](seq iter.Seq2[E, error], include func(e E) bool) iter.Seq2[E, error] {
	return func(yield func(E, error) bool) {
		for e, err := range seq {
			if err != nil {
				yield(e, err)
				return
			}

			if include(e) && !yield(e, nil) {
				return
			}
		}
	}
}

// Keys returns the keys of an iterator over keys and values.
func Keys[K, V any](seq iter.Seq2[K, V]) iter.Seq[K] {
	return func(yield func(K) bool) {
		for k := range seq {
			if !yield(k) {
				return
			}
		}
	}
}

// Repeat endlessly repeats an element as an iterator.
func Repeat[E any](e E) iter.Seq[E] {
	return func(yield func(E) bool) {
		for yield(e) {
		}
	}
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

// SkipLast2 skips the last n elements of an iterator of pairs.
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

// SortedIntersection computes the set-intersection of zero or more sorted iterators.
// For an element to be returned, it must be found in all of the sequences. Values are
// assumed to be sorted. If they are not sorted the intersection will not be valid.
func SortedIntersection[E any](compare func(a, b E) int, seqs ...iter.Seq[E]) iter.Seq[E] {
	seqsWithError := make([]iter.Seq2[E, error], len(seqs))
	for i, seq := range seqs {
		seqsWithError[i] = Zip(seq, Repeat(error(nil)))
	}
	return Keys(SortedIntersectionWithError(compare, seqsWithError...))
}

// SortedIntersectionWithError computes the set-intersection of zero or more sorted iterators.
// For an element to be returned, it must be found in all of the sequences. Values are
// assumed to be sorted. If they are not sorted the intersection will not be valid.
//
// If any error occurs in any iterator it will be returned and stop.
func SortedIntersectionWithError[E any](compare func(a, b E) int, seqs ...iter.Seq2[E, error]) iter.Seq2[E, error] {
	switch len(seqs) {
	case 0:
		return func(_ func(E, error) bool) {}
	case 1:
		return seqs[0]
	case 2:
		return func(yield func(E, error) bool) {
			next1, stop1 := iter.Pull2(seqs[0])
			defer stop1()
			next2, stop2 := iter.Pull2(seqs[1])
			defer stop2()

			value1, err1, ok1 := next1()
			value2, err2, ok2 := next2()
			for ok1 && ok2 {
				if err1 != nil {
					yield(value1, err1)
					return
				}
				if err2 != nil {
					yield(value2, err2)
					return
				}
				switch compare(value1, value2) {
				case -1:
					value1, err1, ok1 = next1()
				case 0:
					if !yield(value1, err1) {
						return
					}
					value1, err1, ok1 = next1()
					value2, err2, ok2 = next2()
				case 1:
					value2, err2, ok2 = next2()
				}
			}
		}
	default:
		return SortedIntersectionWithError(compare,
			SortedIntersectionWithError(compare, seqs[:len(seqs)/2]...),
			SortedIntersectionWithError(compare, seqs[len(seqs)/2:]...))
	}
}

// SortedUnion computes the set-union of zero or more sorted iterators.
// For an element to be returned, it must be found in at least one of the sequences.
// Values are assumed to be sorted and only duplicates are removed.
func SortedUnion[E any](compare func(a, b E) int, seqs ...iter.Seq[E]) iter.Seq[E] {
	seqsWithError := make([]iter.Seq2[E, error], len(seqs))
	for i, seq := range seqs {
		seqsWithError[i] = Zip(seq, Repeat(error(nil)))
	}
	return Keys(SortedUnionWithError(compare, seqsWithError...))
}

// SortedUnionWithError computes the set-union of zero or more sorted iterators.
// For an element to be returned, it must be found in at least one of the sequences.
// Values are assumed to be sorted and only duplicates are removed.
//
// If any error occurs in any iterator it will be returned and stop.
func SortedUnionWithError[E any](compare func(a, b E) int, seqs ...iter.Seq2[E, error]) iter.Seq2[E, error] {
	switch len(seqs) {
	case 0:
		return func(_ func(E, error) bool) {}
	case 1:
		return seqs[0]
	case 2:
		return func(yield func(E, error) bool) {
			next1, stop1 := iter.Pull2(seqs[0])
			defer stop1()
			next2, stop2 := iter.Pull2(seqs[1])
			defer stop2()

			value1, err1, ok1 := next1()
			value2, err2, ok2 := next2()
			for ok1 || ok2 {
				if ok1 && err1 != nil {
					yield(value1, err1)
					return
				}
				if ok2 && err2 != nil {
					yield(value2, err2)
					return
				}
				switch {
				case !ok1:
					if !yield(value2, nil) {
						return
					}
					value2, err2, ok2 = next2()
				case !ok2:
					if !yield(value1, nil) {
						return
					}
					value1, err1, ok1 = next1()
				default:
					switch compare(value1, value2) {
					case -1:
						if !yield(value1, nil) {
							return
						}
						value1, err1, ok1 = next1()
					case 0:
						if !yield(value1, nil) {
							return
						}
						value1, err1, ok1 = next1()
						value2, err2, ok2 = next2()
					case 1:
						if !yield(value2, nil) {
							return
						}
						value2, err2, ok2 = next2()
					}
				}
			}
		}
	default:
		return SortedUnionWithError(compare,
			SortedUnionWithError(compare, seqs[:len(seqs)/2]...),
			SortedUnionWithError(compare, seqs[len(seqs)/2:]...))
	}
}

func Zip[K, V any](seqK iter.Seq[K], seqV iter.Seq[V]) iter.Seq2[K, V] {
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
