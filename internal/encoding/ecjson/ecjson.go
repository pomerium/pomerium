// Package ecjson represents encrypted and compressed content using JSON-based
package ecjson // import "github.com/pomerium/pomerium/internal/encoding/ecjson"

import (
	"bytes"
	"compress/gzip"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"

	"github.com/pomerium/pomerium/internal/cryptutil"
)

// EncryptedCompressedJSON implements SecureEncoder for JSON using an AEAD cipher.
//
// See https://en.wikipedia.org/wiki/Authenticated_encryption
type EncryptedCompressedJSON struct {
	aead cipher.AEAD
}

// New takes a base64 encoded secret key and returns a new XChacha20poly1305 cipher.
func New(aead cipher.AEAD) *EncryptedCompressedJSON {
	return &EncryptedCompressedJSON{aead: aead}
}

// Marshal marshals the interface state as JSON, encrypts the JSON using the cipher
// and base64 encodes the binary value as a string and returns the result
//
// can panic if source of random entropy is exhausted generating a nonce.
func (c *EncryptedCompressedJSON) Marshal(s interface{}) ([]byte, error) {
	// encode json value
	plaintext, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}

	// compress the plaintext bytes
	compressed, err := compress(plaintext)
	if err != nil {
		return nil, err
	}
	// encrypt the compressed JSON bytes
	ciphertext := cryptutil.Encrypt(c.aead, compressed, nil)

	// base64-encode the result
	encoded := base64.RawURLEncoding.EncodeToString(ciphertext)
	return []byte(encoded), nil
}

// Unmarshal takes the marshaled string, base64-decodes into a byte slice, decrypts the
// byte slice the passed cipher, and unmarshals the resulting JSON into the struct pointer passed
func (c *EncryptedCompressedJSON) Unmarshal(data []byte, s interface{}) error {
	// convert base64 string value to bytes
	ciphertext, err := base64.RawURLEncoding.DecodeString(string(data))
	if err != nil {
		return err
	}
	// decrypt the bytes
	compressed, err := cryptutil.Decrypt(c.aead, ciphertext, nil)
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
