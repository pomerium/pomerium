package aead // import "github.com/pomerium/pomerium/internal/aead"

import (
	"bytes"
	"compress/gzip"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"sync"

	miscreant "github.com/miscreant/miscreant-go"
)

const miscreantNonceSize = 16

var algorithmType = "AES-CMAC-SIV"

// Cipher provides methods to encrypt and decrypt values.
type Cipher interface {
	Encrypt([]byte) ([]byte, error)
	Decrypt([]byte) ([]byte, error)
	Marshal(interface{}) (string, error)
	Unmarshal(string, interface{}) error
}

// MiscreantCipher provides methods to encrypt and decrypt values.
// Using an AEAD is a cipher providing authenticated encryption with associated data.
// For a description of the methodology, see https://en.wikipedia.org/wiki/Authenticated_encryption
type MiscreantCipher struct {
	aead cipher.AEAD

	mux sync.Mutex
}

// NewMiscreantCipher returns a new AES Cipher for encrypting values
func NewMiscreantCipher(secret []byte) (*MiscreantCipher, error) {
	aead, err := miscreant.NewAEAD(algorithmType, secret, miscreantNonceSize)
	if err != nil {
		return nil, err
	}
	return &MiscreantCipher{
		aead: aead,
	}, nil
}

// GenerateKey wraps miscreant's GenerateKey function
func GenerateKey() []byte {
	return miscreant.GenerateKey(32)
}

// Encrypt a value using AES-CMAC-SIV
func (c *MiscreantCipher) Encrypt(plaintext []byte) (joined []byte, err error) {
	c.mux.Lock()
	defer c.mux.Unlock()

	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("miscreant error encrypting bytes: %v", r)
		}
	}()
	nonce := miscreant.GenerateNonce(c.aead)
	ciphertext := c.aead.Seal(nil, nonce, plaintext, nil)

	// we return the nonce as part of the returned value
	joined = append(ciphertext[:], nonce[:]...)
	return joined, nil
}

// Decrypt a value using AES-CMAC-SIV
func (c *MiscreantCipher) Decrypt(joined []byte) ([]byte, error) {
	c.mux.Lock()
	defer c.mux.Unlock()

	if len(joined) <= miscreantNonceSize {
		return nil, fmt.Errorf("invalid input size: %d", len(joined))
	}
	// grab out the nonce
	pivot := len(joined) - miscreantNonceSize
	ciphertext := joined[:pivot]
	nonce := joined[pivot:]

	plaintext, err := c.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// Marshal marshals the interface state as JSON, encrypts the JSON using the cipher
// and base64 encodes the binary value as a string and returns the result
func (c *MiscreantCipher) Marshal(s interface{}) (string, error) {
	// encode json value
	plaintext, err := json.Marshal(s)
	if err != nil {
		return "", err
	}
	compressed, err := compress(plaintext)
	if err != nil {
		return "", err
	}
	// encrypt the JSON
	ciphertext, err := c.Encrypt(compressed)
	if err != nil {
		return "", err
	}

	// base64-encode the result
	encoded := base64.RawURLEncoding.EncodeToString(ciphertext)
	return encoded, nil
}

// Unmarshal takes the marshaled string, base64-decodes into a byte slice, decrypts the
// byte slice the pased cipher, and unmarshals the resulting JSON into the struct pointer passed
func (c *MiscreantCipher) Unmarshal(value string, s interface{}) error {
	// convert base64 string value to bytes
	ciphertext, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return err
	}

	// decrypt the bytes
	compressed, err := c.Decrypt(ciphertext)
	if err != nil {
		return err
	}
	// decompress
	plaintext, err := decompress(compressed)
	if err != nil {
		return err
	}
	// unmarshal bytes
	err = json.Unmarshal(plaintext, s)
	if err != nil {
		return err
	}

	return nil
}

func compress(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	writer, err := gzip.NewWriterLevel(&buf, gzip.DefaultCompression)
	if err != nil {
		return nil, fmt.Errorf("aead/compress: failed to create a gzip writer: %q", err)
	}
	if writer == nil {
		return nil, fmt.Errorf("aead/compress: failed to create a gzip writer")
	}
	if _, err = writer.Write(data); err != nil {
		return nil, fmt.Errorf("aead/compress: failed to compress data with err: %q", err)
	}
	if err = writer.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func decompress(data []byte) ([]byte, error) {
	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("aead/compress: failed to create a gzip reader: %q", err)
	}
	defer reader.Close()
	var buf bytes.Buffer
	if _, err = io.Copy(&buf, reader); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
