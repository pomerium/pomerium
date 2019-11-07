package cryptutil // import "github.com/pomerium/pomerium/internal/cryptutil"

import (
	"crypto/cipher"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// NewAEADCipher takes secret key and returns a new XChacha20poly1305 cipher.
func NewAEADCipher(secret []byte) (cipher.AEAD, error) {
	if len(secret) != 32 {
		return nil, fmt.Errorf("cryptutil: got %d bytes but want 32", len(secret))
	}
	return chacha20poly1305.NewX(secret)

}

// NewAEADCipherFromBase64 takes a base64 encoded secret key and returns a new XChacha20poly1305 cipher.
func NewAEADCipherFromBase64(s string) (cipher.AEAD, error) {
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("cryptutil: invalid base64: %v", err)
	}
	return NewAEADCipher(decoded)
}

// Encrypt encrypts a value with optional associated data
//
// Panics if source of randomness fails.
func Encrypt(a cipher.AEAD, data, ad []byte) []byte {
	iv := randomBytes(a.NonceSize())
	ciphertext := a.Seal(nil, iv, data, ad)
	return append(ciphertext, iv...)
}

// Decrypt a value with optional associated data
func Decrypt(a cipher.AEAD, data, ad []byte) ([]byte, error) {
	if len(data) <= a.NonceSize() {
		return nil, fmt.Errorf("cryptutil: invalid input size: %d", len(data))
	}
	size := len(data) - a.NonceSize()
	ciphertext := data[:size]
	nonce := data[size:]
	plaintext, err := a.Open(nil, nonce, ciphertext, ad)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}
