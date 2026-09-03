package tokens

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

func DeriveEncryptionCipher(sharedSecret []byte) (cipher.AEAD, error) {
	r := hkdf.New(sha256.New, sharedSecret, nil, []byte("authenticate-oidc-encryption-key"))
	encryptionKey := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(r, encryptionKey); err != nil {
		return nil, err
	}
	return chacha20poly1305.NewX(encryptionKey)
}

type randomNonceAEAD struct {
	aead cipher.AEAD
}

// Encrypt encrypts a plaintext with a random nonce and the given additional
// data, returning nonce || ciphertext.
func (a randomNonceAEAD) Encrypt(plaintext, additionalData []byte) []byte {
	// Select a random nonce, and leave capacity for the ciphertext.
	n := a.aead.NonceSize()
	capacity := n + len(plaintext) + a.aead.Overhead()
	nonce := make([]byte, n, capacity)
	rand.Read(nonce)

	// Encrypt the message and append the ciphertext to the nonce.
	return a.aead.Seal(nonce, nonce, plaintext, additionalData)
}

// Decrypt accepts a nonce || ciphertext and decrypts using the given additional
// data, returning the plaintext if successful or an error if not.
func (a randomNonceAEAD) Decrypt(ciphertext, additionalData []byte) ([]byte, error) {
	n := a.aead.NonceSize()
	if len(ciphertext) < n {
		return nil, errors.New("ciphertext too short")
	}
	nonce, ciphertext := ciphertext[:n], ciphertext[n:]

	// Decrypt the message and check it wasn't tampered with.
	return a.aead.Open(nil, nonce, ciphertext, additionalData)
}
