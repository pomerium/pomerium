package cryptutil

import (
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"

	"github.com/akamensky/base58"
)

// A KeyEncryptionKey (KEK) is used to implement *envelope encryption*, similar to how data is stored at rest with
// AWS or Google Cloud:
//
//   - AWS: https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#enveloping
//   - Google Cloud: https://cloud.google.com/kms/docs/envelope-encryption
//
// Data is encrypted with a data encryption key (DEK) and that key is stored next to the data encrypted with the KEK.
// Finally the KEK id is also stored with the data.
//
// To decrypt the data you first retrieve the KEK, second decrypt the DEK, and finally decrypt the data using the DEK.
//
//   - Our KEKs are asymmetric Curve25519 keys. We use the *public* key to encrypt the DEK so only the *private* key can
//     decrypt it.
//   - Our DEKs are symmetric XChaCha20Poly1305 keys.
type KeyEncryptionKey interface {
	ID() string
	KeyBytes() []byte

	isKeyEncryptionKey()
}

// KeyEncryptionKeySize is the size of a key encryption key.
const KeyEncryptionKeySize = curve25519.ScalarSize

// PrivateKeyEncryptionKey is a Curve25519 asymmetric private encryption key used to decrypt data encryption keys.
type PrivateKeyEncryptionKey struct {
	data [KeyEncryptionKeySize]byte
}

func (*PrivateKeyEncryptionKey) isKeyEncryptionKey() {}

// NewPrivateKeyEncryptionKey creates a new encryption key from existing bytes.
func NewPrivateKeyEncryptionKey(raw []byte) (*PrivateKeyEncryptionKey, error) {
	if len(raw) != KeyEncryptionKeySize {
		return nil, fmt.Errorf("cryptutil: invalid key encryption key, expected %d bytes, got %d",
			KeyEncryptionKeySize, len(raw))
	}
	kek := new(PrivateKeyEncryptionKey)
	copy(kek.data[:], raw)
	return kek, nil
}

// GenerateKeyEncryptionKey generates a new random key encryption key.
func GenerateKeyEncryptionKey() (*PrivateKeyEncryptionKey, error) {
	raw := randomBytes(KeyEncryptionKeySize)
	return NewPrivateKeyEncryptionKey(raw)
}

// GetKeyEncryptionKeyID derives an id from the key encryption key data itself.
func GetKeyEncryptionKeyID(raw []byte) string {
	return base58.Encode(Hash("KeyEncryptionKey", raw))
}

// Decrypt decrypts data from a NACL anonymous box.
func (kek *PrivateKeyEncryptionKey) Decrypt(ciphertext []byte) ([]byte, error) {
	private := kek
	public := kek.Public()

	opened, ok := box.OpenAnonymous(nil, ciphertext, &public.data, &private.data)
	if !ok {
		return nil, fmt.Errorf("cryptutil: anonymous box decrypt failed")
	}
	return opened, nil
}

// DecryptDataEncryptionKey decrypts a data encryption key.
func (kek *PrivateKeyEncryptionKey) DecryptDataEncryptionKey(ciphertext []byte) (*DataEncryptionKey, error) {
	raw, err := kek.Decrypt(ciphertext)
	if err != nil {
		return nil, err
	}
	return NewDataEncryptionKey(raw)
}

// ID returns the private key's id.
func (kek *PrivateKeyEncryptionKey) ID() string {
	return kek.Public().id
}

// KeyBytes returns the private key encryption key's raw bytes.
func (kek *PrivateKeyEncryptionKey) KeyBytes() []byte {
	data := make([]byte, KeyEncryptionKeySize)
	copy(data, kek.data[:])
	return data
}

// Public returns the private key's public key.
func (kek *PrivateKeyEncryptionKey) Public() *PublicKeyEncryptionKey {
	// taken from NACL box.GenerateKey
	var publicKey [32]byte
	curve25519.ScalarBaseMult(&publicKey, &kek.data)
	return &PublicKeyEncryptionKey{
		id:   GetKeyEncryptionKeyID(kek.data[:]),
		data: publicKey,
	}
}

// PublicKeyEncryptionKey is a Curve25519 asymmetric public encryption key used to encrypt data encryption keys.
type PublicKeyEncryptionKey struct {
	id   string
	data [KeyEncryptionKeySize]byte
}

func (*PublicKeyEncryptionKey) isKeyEncryptionKey() {}

// NewPublicKeyEncryptionKey creates a new encryption key from existing bytes.
func NewPublicKeyEncryptionKey(raw []byte) (*PublicKeyEncryptionKey, error) {
	return NewPublicKeyEncryptionKeyWithID(GetKeyEncryptionKeyID(raw), raw)
}

// NewPublicKeyEncryptionKeyWithID creates a new encryption key from an existing id and bytes.
func NewPublicKeyEncryptionKeyWithID(id string, raw []byte) (*PublicKeyEncryptionKey, error) {
	if len(raw) != KeyEncryptionKeySize {
		return nil, fmt.Errorf("cryptutil: invalid key encryption key, expected %d bytes, got %d",
			KeyEncryptionKeySize, len(raw))
	}
	kek := &PublicKeyEncryptionKey{
		id: id,
	}
	copy(kek.data[:], raw)
	return kek, nil
}

// ID returns the public key's id.
func (kek *PublicKeyEncryptionKey) ID() string {
	return kek.id
}

// KeyBytes returns the public key's raw bytes.
func (kek *PublicKeyEncryptionKey) KeyBytes() []byte {
	data := make([]byte, KeyEncryptionKeySize)
	copy(data, kek.data[:])
	return data
}

// Encrypt encrypts data using a NACL anonymous box.
func (kek *PublicKeyEncryptionKey) Encrypt(plaintext []byte) ([]byte, error) {
	sealed, err := box.SealAnonymous(nil, plaintext, &kek.data, rand.Reader)
	if err != nil { // only fails on rand.Read errors
		return nil, fmt.Errorf("cryptutil: anonymous box encrypt failed: %w", err)
	}
	return sealed, nil
}

// EncryptDataEncryptionKey encrypts a DataEncryptionKey.
func (kek *PublicKeyEncryptionKey) EncryptDataEncryptionKey(dek *DataEncryptionKey) ([]byte, error) {
	return kek.Encrypt(dek.data[:])
}

// A KeyEncryptionKeySource gets private key encryption keys based on their id.
type KeyEncryptionKeySource interface {
	GetKeyEncryptionKey(id string) (*PrivateKeyEncryptionKey, error)
}

// A KeyEncryptionKeySourceFunc implements the KeyEncryptionKeySource interface using a function.
type KeyEncryptionKeySourceFunc func(id string) (*PrivateKeyEncryptionKey, error)

// GetKeyEncryptionKey gets the key encryption key by calling the underlying function.
func (src KeyEncryptionKeySourceFunc) GetKeyEncryptionKey(id string) (*PrivateKeyEncryptionKey, error) {
	return src(id)
}
