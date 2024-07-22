// Package hashutil provides NON-CRYPTOGRAPHIC utility functions for hashing.
//
// http://cyan4973.github.io/xxHash/
package hashutil

import (
	"encoding/binary"

	"github.com/cespare/xxhash/v2"
	"github.com/mitchellh/hashstructure/v2"
)

// MustHash returns the xxhash of an arbitrary value or struct. Returns 0
// on error.
// NOT SUITABLE FOR CRYTOGRAPHIC HASHING.
func MustHash(v any) uint64 {
	hash, err := Hash(v)
	if err != nil {
		hash = 0
	}
	return hash
}

// Hash returns the xxhash of an arbitrary value or struct.
// NOT SUITABLE FOR CRYTOGRAPHIC HASHING.
func Hash(v any) (uint64, error) {
	opts := &hashstructure.HashOptions{
		Hasher: xxhash.New(),
	}
	return hashstructure.Hash(v, hashstructure.FormatV2, opts)
}

// MapHash efficiently computes a non-cryptographic hash of a map of strings.
func MapHash(iv uint64, m map[string]string) uint64 {
	accum := iv
	var buf [16]byte
	for k, v := range m {
		binary.BigEndian.PutUint64(buf[0:8], xxhash.Sum64String(k))
		binary.BigEndian.PutUint64(buf[8:16], xxhash.Sum64String(v))
		accum ^= xxhash.Sum64(buf[:])
	}
	return accum
}
