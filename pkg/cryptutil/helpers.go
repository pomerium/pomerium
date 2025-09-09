package cryptutil

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
)

// DefaultKeySize is the default key size in bytes.
const DefaultKeySize = 32

// NewKey generates a random 32-byte (256 bit) key.
//
// Panics if source of randomness fails.
func NewKey() []byte {
	return randomBytes(DefaultKeySize)
}

// NewBase64Key generates a random base64 encoded 32-byte key.
//
// Panics if source of randomness fails.
func NewBase64Key() string {
	return NewRandomStringN(DefaultKeySize)
}

// NewRandomStringN returns base64 encoded random string of a given num of bytes.
//
// Panics if source of randomness fails.
func NewRandomStringN(c int) string {
	return base64.StdEncoding.EncodeToString(randomBytes(c))
}

// NewRandomUInt32 returns a random uint32 that will never be 0.
//
// Panics if source of randomness fails.
func NewRandomUInt32() uint32 {
	for {
		i := binary.LittleEndian.Uint32(randomBytes(4))
		if i != 0 {
			return i
		}
	}
}

// NewRandomUInt64 returns a random uint64 that will never be 0.
//
// Panics if source of randomness fails.
func NewRandomUInt64() uint64 {
	for {
		i := binary.LittleEndian.Uint64(randomBytes(8))
		if i != 0 {
			return i
		}
	}
}

// randomBytes generates C number of random bytes suitable for cryptographic
// operations.
//
// Panics if source of randomness fails.
func randomBytes(c int) []byte {
	if c < 0 {
		c = DefaultKeySize
	}
	b := make([]byte, c)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}
