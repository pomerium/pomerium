// Package counter implements linear counter estimator
package counter

import (
	"hash/crc32"
	"math"

	"github.com/bits-and-blooms/bitset"
)

const (
	// DefaultCap max capacity for the counter
	DefaultCap = 1 << 19
	loadFactor = 4
)

// Counter implements a simple probabilistic counter estimator with 1% estimation accuracy
// as described in https://www.waitingforcode.com/big-data-algorithms/cardinality-estimation-linear-probabilistic-counting/read
type Counter struct {
	Bits *bitset.BitSet `json:"bits"`
}

// New creates a counter for the maximum amount unique elements provided
func New(capacity uint) *Counter {
	return &Counter{
		// from paper: a load factor (number of unique values/hash table size) much larger
		// than 1.0 (e.g., 12) can be used for accurate estimation (e.g., 1% of error)
		Bits: bitset.New(capacity / loadFactor),
	}
}

// FromBinary unmarshals counter state
func FromBinary(data []byte) (*Counter, error) {
	pc := &Counter{
		Bits: &bitset.BitSet{},
	}
	if err := pc.Bits.UnmarshalBinary(data); err != nil {
		return nil, err
	}
	return pc, nil
}

// ToBinary marshals counter state
func (c *Counter) ToBinary() ([]byte, error) {
	return c.Bits.MarshalBinary()
}

// Reset the counter
func (c *Counter) Reset() {
	c.Bits.ClearAll()
}

// Mark marks key as present in the set
func (c *Counter) Mark(key string) {
	hash := crc32.ChecksumIEEE([]byte(key))
	c.Bits.Set(uint(hash) % c.Bits.Len())
}

// Count returns an estimate of distinct elements in the set
func (c *Counter) Count() uint {
	size := float64(c.Bits.Len())
	zeros := size - float64(c.Bits.Count())
	return uint(-1 * size * math.Log(zeros/size))
}
