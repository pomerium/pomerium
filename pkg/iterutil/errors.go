package iterutil

import "iter"

// An ErrorSeq is an iterator of values with errors.
type ErrorSeq[E any] = iter.Seq2[E, error]

// ApplyWithError creates a new ErrorSeq that applies a transformation
// function to the simple sequence of elements.
func ApplyWithError[E any](seq ErrorSeq[E], transform func(seq iter.Seq[E]) iter.Seq[E]) ErrorSeq[E] {
	var errDuringIteration error
	seq1 := func(yield func(E) bool) {
		for e, err := range seq {
			if err != nil {
				errDuringIteration = err
				return
			}
			if !yield(e) {
				return
			}
		}
	}
	seq1 = transform(seq1)
	return func(yield func(E, error) bool) {
		for e := range seq1 {
			if !yield(e, nil) {
				return
			}
		}
		if errDuringIteration != nil {
			var zero E
			yield(zero, errDuringIteration)
		}
	}
}

// CollectWithError takes a sequence of values and errors and turns it
// into a slice or error.
func CollectWithError[E any](seq ErrorSeq[E]) ([]E, error) {
	var s []E
	for e, err := range seq {
		if err != nil {
			return nil, err
		}
		s = append(s, e)
	}
	return s, nil
}

// FilterWithError implements Filter for an ErrorSeq.
func FilterWithError[E any](seq ErrorSeq[E], include func(e E) bool) ErrorSeq[E] {
	return ApplyWithError(seq, func(seq iter.Seq[E]) iter.Seq[E] {
		return Filter(seq, include)
	})
}

// SkipLastWithError implements SkipLast for an ErrorSeq.
func SkipLastWithError[E any](seq ErrorSeq[E], n int) ErrorSeq[E] {
	return ApplyWithError(seq, func(seq iter.Seq[E]) iter.Seq[E] {
		return SkipLast(seq, n)
	})
}

// SortedIntersectionWithError implements SortedIntersection for an ErrorSeq.
func SortedIntersectionWithError[E any](compare func(a, b E) int, seqs ...ErrorSeq[E]) ErrorSeq[E] {
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

// SortedUnionWithError implements SortedUnion for an ErrorSeq.
func SortedUnionWithError[E any](compare func(a, b E) int, seqs ...ErrorSeq[E]) ErrorSeq[E] {
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
