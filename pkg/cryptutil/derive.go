package cryptutil

import (
	"crypto/hkdf"
	"crypto/sha256"
	"fmt"
)

// DeriveKey derives a key from another key using hkdf.
func DeriveKey(baseKey []byte, name string) []byte {
	newKey, err := hkdf.Key(sha256.New, baseKey, nil, name, len(baseKey))
	// the only way Key returns an error is if the inputs are too short, so just panic
	if err != nil {
		panic(fmt.Errorf("error deriving key: %w", err))
	}
	return newKey
}
