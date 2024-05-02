// Package hashutil provides NON-CRYPTOGRAPHIC utility functions for hashing.
//
// http://cyan4973.github.io/xxHash/
package hashutil

import (
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
