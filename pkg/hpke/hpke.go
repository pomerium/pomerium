// Package hpke contains functions for working with Hybrid Public Key Encryption.
package hpke

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/cloudflare/circl/hpke"
	"github.com/cloudflare/circl/kem"
)

var (
	kemID  = hpke.KEM_X25519_HKDF_SHA256
	kdfID  = hpke.KDF_HKDF_SHA256
	aeadID = hpke.AEAD_ChaCha20Poly1305
	suite  = hpke.NewSuite(kemID, kdfID, aeadID)

	kdfExpandInfo = []byte("pomerium/hpke")
)

// PrivateKey is an HPKE private key.
type PrivateKey struct {
	key kem.PrivateKey
}

// DerivePrivateKey derives a private key from a seed. The same seed will always result in the same private key.
func DerivePrivateKey(seed []byte) *PrivateKey {
	pk := kdfID.Extract(seed, nil)
	data := kdfID.Expand(pk, kdfExpandInfo, uint(kemID.Scheme().SeedSize()))
	_, key := kemID.Scheme().DeriveKeyPair(data)
	return &PrivateKey{key: key}
}

// GeneratePrivateKey generates an HPKE private key.
func GeneratePrivateKey() (*PrivateKey, error) {
	_, privateKey, err := kemID.Scheme().GenerateKeyPair()
	if err != nil {
		return nil, err
	}
	return &PrivateKey{key: privateKey}, nil
}

// PrivateKeyFromString takes a string and returns a PrivateKey.
func PrivateKeyFromString(raw string) (*PrivateKey, error) {
	bs, err := decode(raw)
	if err != nil {
		return nil, err
	}

	key, err := kemID.Scheme().UnmarshalBinaryPrivateKey(bs)
	if err != nil {
		return nil, err
	}

	return &PrivateKey{key: key}, nil
}

// PublicKey returns the public key for the private key.
func (key *PrivateKey) PublicKey() *PublicKey {
	if key == nil || key.key == nil {
		return nil
	}

	return &PublicKey{key: key.key.Public()}
}

// MarshalJSON returns the JSON Web Key representation of the private key.
func (key *PrivateKey) MarshalJSON() ([]byte, error) {
	return json.Marshal(JWK{
		Type:  jwkType,
		ID:    jwkID,
		Curve: jwkCurve,
		X:     key.PublicKey().String(),
		D:     key.String(),
	})
}

// String converts the private key into a string.
func (key *PrivateKey) String() string {
	if key == nil || key.key == nil {
		return ""
	}

	bs, err := key.key.MarshalBinary()
	if err != nil {
		// this should not happen
		panic(fmt.Sprintf("failed to marshal private HPKE key: %v", err))
	}

	return base64.RawStdEncoding.EncodeToString(bs)
}

// PublicKey is an HPKE public key.
type PublicKey struct {
	key kem.PublicKey
}

// PublicKeyFromBytes converts raw bytes into a public key.
func PublicKeyFromBytes(raw []byte) (*PublicKey, error) {
	key, err := kemID.Scheme().UnmarshalBinaryPublicKey(raw)
	if err != nil {
		return nil, err
	}

	return &PublicKey{key: key}, nil
}

// PublicKeyFromString converts a string into a public key.
func PublicKeyFromString(raw string) (*PublicKey, error) {
	bs, err := decode(raw)
	if err != nil {
		return nil, err
	}

	key, err := kemID.Scheme().UnmarshalBinaryPublicKey(bs)
	if err != nil {
		return nil, err
	}

	return &PublicKey{key: key}, nil
}

// Equals returns true if the two keys are equivalent.
func (key *PublicKey) Equals(other *PublicKey) bool {
	if key == nil && other == nil {
		return true
	} else if key == nil || other == nil {
		return false
	}

	if key.key == nil && other.key == nil {
		return true
	} else if key.key == nil || other.key == nil {
		return false
	}
	return key.key.Equal(other.key)
}

// Bytes returns the public key as raw bytes.
func (key *PublicKey) Bytes() []byte {
	if key == nil || key.key == nil {
		return nil
	}

	bs, err := key.key.MarshalBinary()
	if err != nil {
		// this should not happen
		panic(fmt.Sprintf("failed to marshal public HPKE key: %v", err))
	}
	return bs
}

// MarshalJSON returns the JSON Web Key representation of the public key.
func (key *PublicKey) MarshalJSON() ([]byte, error) {
	return json.Marshal(JWK{
		Type:  jwkType,
		ID:    jwkID,
		Curve: jwkCurve,
		X:     key.String(),
	})
}

// String converts a public key into a string.
func (key *PublicKey) String() string {
	if key == nil || key.key == nil {
		return ""
	}

	bs, err := key.key.MarshalBinary()
	if err != nil {
		// this should not happen
		panic(fmt.Sprintf("failed to marshal public HPKE key: %v", err))
	}

	return encode(bs)
}

// Seal seales a message using HPKE.
func Seal(
	senderPrivateKey *PrivateKey,
	receiverPublicKey *PublicKey,
	message []byte,
) (sealed []byte, err error) {
	if senderPrivateKey == nil {
		return nil, fmt.Errorf("hpke: sender private key cannot be nil")
	}
	if receiverPublicKey == nil {
		return nil, fmt.Errorf("hpke: receiver public key cannot be nil")
	}

	sender, err := suite.NewSender(receiverPublicKey.key, nil)
	if err != nil {
		return nil, fmt.Errorf("hpke: error creating sender: %w", err)
	}

	enc, sealer, err := sender.SetupAuth(rand.Reader, senderPrivateKey.key)
	if err != nil {
		return nil, fmt.Errorf("hpke: error creating sealer: %w", err)
	}

	ct, err := sealer.Seal(message, nil)
	if err != nil {
		return nil, fmt.Errorf("hpke: error sealing message: %w", err)
	}

	return append(enc, ct...), nil
}

// Open opens a message using HPKE.
func Open(
	receiverPrivateKey *PrivateKey,
	senderPublicKey *PublicKey,
	sealed []byte,
) (message []byte, err error) {
	if receiverPrivateKey == nil {
		return nil, fmt.Errorf("hpke: receiver private key cannot be nil")
	}
	if senderPublicKey == nil {
		return nil, fmt.Errorf("hpke: sender public key cannot be nil")
	}

	encSize := kemID.Scheme().SharedKeySize()
	if len(sealed) < encSize {
		return nil, fmt.Errorf("hpke: invalid sealed message")
	}
	enc, sealed := sealed[:encSize], sealed[encSize:]

	receiver, err := suite.NewReceiver(receiverPrivateKey.key, nil)
	if err != nil {
		return nil, fmt.Errorf("hpke: error creating receiver: %w", err)
	}

	opener, err := receiver.SetupAuth(enc, senderPublicKey.key)
	if err != nil {
		return nil, fmt.Errorf("hpke: error creating opener: %w", err)
	}

	message, err = opener.Open(sealed, nil)
	if err != nil {
		return nil, fmt.Errorf("hpke: error opening sealed message: %w", err)
	}

	return message, nil
}

func decode(raw string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(raw)
}

func encode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}
