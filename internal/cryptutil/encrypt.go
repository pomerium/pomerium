package cryptutil // import "github.com/pomerium/pomerium/internal/cryptutil"

import (
	"bytes"
	"compress/gzip"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"

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

// SecureEncoder provides and interface for to encrypt and decrypting structures .
type SecureEncoder interface {
	Marshal(interface{}) (string, error)
	Unmarshal(string, interface{}) error
}

// SecureJSONEncoder implements SecureEncoder for JSON using an AEAD cipher.
//
// See https://en.wikipedia.org/wiki/Authenticated_encryption
type SecureJSONEncoder struct {
	aead cipher.AEAD
}

// NewSecureJSONEncoder takes a base64 encoded secret key and returns a new XChacha20poly1305 cipher.
func NewSecureJSONEncoder(aead cipher.AEAD) SecureEncoder {
	return &SecureJSONEncoder{aead: aead}
}

// Marshal marshals the interface state as JSON, encrypts the JSON using the cipher
// and base64 encodes the binary value as a string and returns the result
//
// can panic if source of random entropy is exhausted generating a nonce.
func (c *SecureJSONEncoder) Marshal(s interface{}) (string, error) {
	// encode json value
	plaintext, err := json.Marshal(s)
	if err != nil {
		return "", err
	}
	// compress the plaintext bytes
	compressed, err := compress(plaintext)
	if err != nil {
		return "", err
	}
	// encrypt the compressed JSON bytes
	ciphertext := Encrypt(c.aead, compressed, nil)

	// base64-encode the result
	encoded := base64.RawURLEncoding.EncodeToString(ciphertext)
	return encoded, nil
}

// Unmarshal takes the marshaled string, base64-decodes into a byte slice, decrypts the
// byte slice the passed cipher, and unmarshals the resulting JSON into the struct pointer passed
func (c *SecureJSONEncoder) Unmarshal(value string, s interface{}) error {
	// convert base64 string value to bytes
	ciphertext, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return err
	}
	// decrypt the bytes
	compressed, err := Decrypt(c.aead, ciphertext, nil)
	if err != nil {
		return err
	}
	// decompress the unencrypted bytes
	plaintext, err := decompress(compressed)
	if err != nil {
		return err
	}
	// unmarshal the unencrypted bytes
	err = json.Unmarshal(plaintext, s)
	if err != nil {
		return err
	}
	return nil
}

// compress gzips a set of bytes
func compress(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	writer, err := gzip.NewWriterLevel(&buf, gzip.DefaultCompression)
	if err != nil {
		return nil, fmt.Errorf("cryptutil: failed to create a gzip writer: %q", err)
	}
	if writer == nil {
		return nil, fmt.Errorf("cryptutil: failed to create a gzip writer")
	}
	if _, err = writer.Write(data); err != nil {
		return nil, fmt.Errorf("cryptutil: failed to compress data with err: %q", err)
	}
	if err = writer.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// decompress un-gzips a set of bytes
func decompress(data []byte) ([]byte, error) {
	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("cryptutil: failed to create a gzip reader: %q", err)
	}
	defer reader.Close()
	var buf bytes.Buffer
	if _, err = io.Copy(&buf, reader); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
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
