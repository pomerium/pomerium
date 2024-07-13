// Package hashutil provides NON-CRYPTOGRAPHIC utility functions for hashing.
//
// http://cyan4973.github.io/xxHash/
package hashutil

import (
	"sync"

	"github.com/cespare/xxhash/v2"
	"github.com/mitchellh/hashstructure/v2"
	"github.com/ugorji/go/codec"
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
	if cs, ok := v.(codec.Selfer); ok {
		return hashCodecSelfer(cs)
	}
	opts := &hashstructure.HashOptions{
		Hasher: xxhash.New(),
	}
	return hashstructure.Hash(v, hashstructure.FormatV2, opts)
}

var msgpackHandle = &codec.MsgpackHandle{}

func init() {
	msgpackHandle.Canonical = true
	// msgpackHandle.StructToArray = true
	// msgpackHandle.StringToRaw = true
}

var encoderPool = sync.Pool{
	New: func() any {
		return codec.NewEncoder(nil, msgpackHandle)
	},
}

var hashPool = sync.Pool{
	New: func() any {
		return xxhash.New()
	},
}

func hashCodecSelfer(v codec.Selfer) (uint64, error) {
	hash := hashPool.Get().(*xxhash.Digest)
	hash.Reset()
	encoder := encoderPool.Get().(*codec.Encoder)
	encoder.Reset(hash)
	err := encoder.Encode(v)
	encoderPool.Put(encoder)
	if err != nil {
		hashPool.Put(hash)
		return 0, err
	}
	sum := hash.Sum64()
	hashPool.Put(hash)
	return sum, nil
}
