package cryptutil

import (
	"crypto/cipher"
	"encoding/base64"
	"fmt"

	lru "github.com/hashicorp/golang-lru/v2"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	// DataEncryptionKeySize is the size of a data encryption key.
	DataEncryptionKeySize = chacha20poly1305.KeySize
	// DataEncryptionKeyCacheSize is the number of DEKs to keep in the LRU cache.
	DataEncryptionKeyCacheSize = 20
)

// A DataEncryptionKey is an XChaCha20Poly1305 symmetric encryption key. For more details
// see the documentation on KeyEncryptionKeys.
type DataEncryptionKey struct {
	data   [DataEncryptionKeySize]byte
	cipher cipher.AEAD
}

// NewDataEncryptionKey returns a new DataEncryptionKey from existing bytes.
func NewDataEncryptionKey(raw []byte) (*DataEncryptionKey, error) {
	if len(raw) != DataEncryptionKeySize {
		return nil, fmt.Errorf("cryptutil: invalid data encryption key, expected %d bytes, got %d",
			DataEncryptionKeySize, len(raw))
	}
	dek := new(DataEncryptionKey)
	copy(dek.data[:], raw)
	dek.cipher, _ = chacha20poly1305.NewX(raw) // only errors on invalid size
	return dek, nil
}

// GenerateDataEncryptionKey generates a new random data encryption key.
func GenerateDataEncryptionKey() (*DataEncryptionKey, error) {
	raw := randomBytes(DataEncryptionKeySize)
	return NewDataEncryptionKey(raw)
}

// Decrypt decrypts encrypted data using the data encryption key.
func (dek *DataEncryptionKey) Decrypt(ciphertext []byte) ([]byte, error) {
	return Decrypt(dek.cipher, ciphertext, nil)
}

// DecryptString decrypts an encrypted string using the data encryption key and base64 encoding.
func (dek *DataEncryptionKey) DecryptString(ciphertext string) (string, error) {
	ciphertextBytes, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}
	plaintextBytes, err := dek.Decrypt(ciphertextBytes)
	if err != nil {
		return "", err
	}
	return string(plaintextBytes), nil
}

// Encrypt encrypts data using the data encryption key.
func (dek *DataEncryptionKey) Encrypt(plaintext []byte) []byte {
	return Encrypt(dek.cipher, plaintext, nil)
}

// EncryptString encrypts a string using the data encryption key and base64 encoding.
func (dek *DataEncryptionKey) EncryptString(plaintext string) string {
	bs := dek.Encrypt([]byte(plaintext))
	return base64.StdEncoding.EncodeToString(bs)
}

// KeyBytes returns the private key encryption key's raw bytes.
func (dek *DataEncryptionKey) KeyBytes() []byte {
	data := make([]byte, DataEncryptionKeySize)
	copy(data, dek.data[:])
	return data
}

// A DataEncryptionKeyCache caches recently used data encryption keys based on their
// encrypted representation. The cache is safe for concurrent read and write access.
//
// Internally an LRU cache is used and the encrypted DEK bytes are converted to strings
// to allow usage as hash map keys.
type DataEncryptionKeyCache struct {
	lru *lru.Cache[string, *DataEncryptionKey]
}

// NewDataEncryptionKeyCache creates a new DataEncryptionKeyCache.
func NewDataEncryptionKeyCache() *DataEncryptionKeyCache {
	c, _ := lru.New[string, *DataEncryptionKey](DataEncryptionKeyCacheSize) // only errors if size <= 0
	return &DataEncryptionKeyCache{lru: c}
}

// Get returns a data encryption key if available.
func (cache *DataEncryptionKeyCache) Get(encryptedDEK []byte) (*DataEncryptionKey, bool) {
	return cache.lru.Get(string(encryptedDEK))
}

// Put stores a data encryption key by its encrypted representation.
func (cache *DataEncryptionKeyCache) Put(encryptedDEK []byte, dek *DataEncryptionKey) {
	cache.lru.Add(string(encryptedDEK), dek)
}
