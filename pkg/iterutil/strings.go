package iterutil

import (
	"iter"
	"slices"
)

// CollectStrings collects a slice of T, where T is a string.
func CollectStrings[T ~string](seq iter.Seq[T]) []string {
	return slices.Collect(Convert(seq, func(e T) string {
		return string(e)
	}))
}
