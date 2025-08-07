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
