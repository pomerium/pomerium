package metrics

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBucketize(t *testing.T) {
	tests := []struct {
		name      string
		num       int
		maxBucket int
		expected  string
	}{
		{"zero", 0, 1000, "1-9"},
		{"negative", -5, 1000, "1-9"},
		{"single digit", 4, 1000, "1-9"},
		{"boundary 9", 9, 1000, "1-9"},
		{"tens", 44, 1000, "10-99"},
		{"boundary 10", 10, 1000, "10-99"},
		{"boundary 99", 99, 1000, "10-99"},
		{"hundreds", 500, 1000, "100-999"},
		{"at max bucket", 1000, 1000, "1000+"},
		{"above max bucket", 5000, 1000, "1000+"},
		{"small max bucket", 50, 100, "10-99"},
		{"max bucket caps upper", 55, 100, "10-99"},
		{"at small max", 100, 100, "100+"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, Bucketize(tt.num, tt.maxBucket))
		})
	}
}
