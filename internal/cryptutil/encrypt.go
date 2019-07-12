package cryptutil // import "github.com/pomerium/pomerium/internal/cryptutil"

import (
	"bytes"
	"compress/gzip"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

// defaultKeySize is set to 256 bits / 32 bytes
const defaultKeySize = 32

// GenerateKey generates a random 32-byte key.
//
// Panics if source of randomness fails.
func GenerateKey() []byte {
	return randomBytes(defaultKeySize)
}

// GenerateRandomString returns base64 encoded securely generated random string
// of a given set of bytes.
//
// Panics if source of randomness fails.
func GenerateRandomString(c int) string {
	return base64.StdEncoding.EncodeToString(randomBytes(c))
}

func randomBytes(c int) []byte {
	if c < 0 {
		c = defaultKeySize
	}
	b := make([]byte, c)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

// Cipher provides methods to encrypt and decrypt values.
type Cipher interface {
	Encrypt([]byte) ([]byte, error)
	Decrypt([]byte) ([]byte, error)
	Marshal(interface{}) (string, error)
	Unmarshal(string, interface{}) error
}

// XChaCha20Cipher provides methods to encrypt and decrypt values.
// Using an AEAD is a cipher providing authenticated encryption with associated data.
// For a description of the methodology, see https://en.wikipedia.org/wiki/Authenticated_encryption
type XChaCha20Cipher struct {
	aead cipher.AEAD
}

// NewCipher takes secret key and returns a new XChacha20poly1305 cipher.
func NewCipher(secret []byte) (*XChaCha20Cipher, error) {
	aead, err := chacha20poly1305.NewX(secret)
	if err != nil {
		return nil, err
	}
	return &XChaCha20Cipher{
		aead: aead,
	}, nil
}

// GenerateNonce generates a random nonce.
// Panics if source of randomness fails.
func (c *XChaCha20Cipher) GenerateNonce() []byte {
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		panic(err)
	}
	return nonce
}

// Encrypt a value using XChaCha20-Poly1305
func (c *XChaCha20Cipher) Encrypt(plaintext []byte) (joined []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("internal/aead: error encrypting bytes: %v", r)
		}
	}()
	nonce := c.GenerateNonce()

	ciphertext := c.aead.Seal(nil, nonce, plaintext, nil)

	// we return the nonce as part of the returned value
	joined = append(ciphertext[:], nonce[:]...)
	return joined, nil
}

// Decrypt a value using XChaCha20-Poly1305
func (c *XChaCha20Cipher) Decrypt(joined []byte) ([]byte, error) {
	if len(joined) <= c.aead.NonceSize() {
		return nil, fmt.Errorf("internal/aead: invalid input size: %d", len(joined))
	}
	// grab out the nonce
	pivot := len(joined) - c.aead.NonceSize()
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
func (c *XChaCha20Cipher) Marshal(s interface{}) (string, error) {
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
	ciphertext, err := c.Encrypt(compressed)
	if err != nil {
		return "", err
	}
	// base64-encode the result
	encoded := base64.RawURLEncoding.EncodeToString(ciphertext)
	return encoded, nil
}

// Unmarshal takes the marshaled string, base64-decodes into a byte slice, decrypts the
// byte slice the passed cipher, and unmarshals the resulting JSON into the struct pointer passed
func (c *XChaCha20Cipher) Unmarshal(value string, s interface{}) error {
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

func compress(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	writer, err := gzip.NewWriterLevel(&buf, gzip.DefaultCompression)
	if err != nil {
		return nil, fmt.Errorf("internal/aead: failed to create a gzip writer: %q", err)
	}
	if writer == nil {
		return nil, fmt.Errorf("internal/aead: failed to create a gzip writer")
	}
	if _, err = writer.Write(data); err != nil {
		return nil, fmt.Errorf("internal/aead: failed to compress data with err: %q", err)
	}
	if err = writer.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func decompress(data []byte) ([]byte, error) {
	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("internal/aead: failed to create a gzip reader: %q", err)
	}
	defer reader.Close()
	var buf bytes.Buffer
	if _, err = io.Copy(&buf, reader); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
