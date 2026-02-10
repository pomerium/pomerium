package metrics

import "fmt"

// Bucketize takes an input number and finds the bucket interval
// that matches the closeset base 10 power.
// For example:
// 4 --> 1-9
// 44 -> 10-99
// and so on.
func Bucketize(num int, maxBucket int) string {
	if num < 0 {
		num = 0
	}

	if num >= maxBucket {
		return fmt.Sprintf("%d+", maxBucket)
	}

	bucket := 1
	for bucket*10 <= num {
		bucket *= 10
	}

	lower := bucket
	upper := min(bucket*10-1, maxBucket)

	return fmt.Sprintf("%d-%d", lower, upper)
}
