// Package hashutil provides NON-CRYPTOGRAPHIC utility functions for hashing
package hashutil

import (
	"github.com/cespare/xxhash/v2"
	"github.com/mitchellh/hashstructure"
)

// Hash returns the xxhash value of an arbitrary value or struct. Returns 0
// on error. NOT SUITABLE FOR CRYTOGRAPHIC HASHING.
//
// http://cyan4973.github.io/xxHash/
func Hash(v interface{}) uint64 {
	opts := &hashstructure.HashOptions{
		Hasher: xxhash.New(),
	}
	hash, err := hashstructure.Hash(v, opts)
	if err != nil {
		hash = 0
	}
	return hash
}
