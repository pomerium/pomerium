package cryptutil

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"time"

	"github.com/akamensky/base58"
	"github.com/google/uuid"
)

// TokenLength is the length of a token.
const TokenLength = 16

// A Token is a globally unique identifier.
type Token [TokenLength]byte

// NewRandomToken returns a new random Token (via a random UUID).
func NewRandomToken() (tok Token) {
	bs := uuid.New()
	copy(tok[:], bs[:])
	return tok
}

// TokenFromString parses a base58-encoded string into a token.
func TokenFromString(rawstr string) (tok Token, ok bool) {
	result, _ := base58.Decode(rawstr)
	if len(result) != TokenLength {
		return tok, false
	}
	copy(tok[:], result[:TokenLength])
	return tok, true
}

// String returns the Token as a base58-encoded string.
func (tok Token) String() string {
	bs := make([]byte, TokenLength)
	copy(bs, tok[:])
	return base58.Encode(bs)
}

// UUID returns the token as a UUID.
func (tok Token) UUID() uuid.UUID {
	var id uuid.UUID
	copy(id[:], tok[:])
	return id
}

// A SecretToken is made up of an id and a secret.
type SecretToken struct {
	ID     Token
	Secret Token
}

// SecretTokenFromString parses a base58-encoded string into a secret token.
func SecretTokenFromString(rawstr string) (tok SecretToken, ok bool) {
	result, _ := base58.Decode(rawstr)
	if len(result) != TokenLength*2 {
		return tok, false
	}
	copy(tok.ID[:], result[:TokenLength])
	copy(tok.Secret[:], result[TokenLength:])
	return tok, true
}

// String returns the SecretToken as a base58-encoded string.
func (tok SecretToken) String() string {
	bs := make([]byte, TokenLength*2)
	copy(bs[:TokenLength], tok.ID[:])
	copy(bs[TokenLength:], tok.Secret[:])
	return base58.Encode(bs)
}

// errors related to the SecureToken
var (
	ErrExpired = errors.New("expired")
	ErrInvalid = errors.New("invalid")
)

const (
	// SecureTokenTimeLength is the length of the time part of the SecureToken.
	SecureTokenTimeLength = 8
	// SecureTokenHMACLength is the length of the HMAC part of the SecureToken.
	SecureTokenHMACLength = 32
	// SecureTokenLength is the byte length of a SecureToken.
	SecureTokenLength = TokenLength + SecureTokenTimeLength + SecureTokenHMACLength
)

// A SecureToken is an HMAC'd Token with an expiration time.
type SecureToken [SecureTokenLength]byte

// GenerateSecureToken generates a SecureToken from the given key, expiry and token.
func GenerateSecureToken(key []byte, expiry time.Time, token Token) SecureToken {
	var secureToken SecureToken
	copy(secureToken[:], token[:])
	binary.BigEndian.PutUint64(secureToken[TokenLength:], uint64(expiry.UnixMilli()))
	h := secureToken.computeHMAC(key)
	copy(secureToken[TokenLength+SecureTokenTimeLength:], h[:])
	return secureToken
}

// SecureTokenFromString parses a base58-encoded string into a SecureToken.
func SecureTokenFromString(rawstr string) (secureToken SecureToken, ok bool) {
	result, _ := base58.Decode(rawstr)
	if len(result) != SecureTokenLength {
		return secureToken, false
	}
	copy(secureToken[:], result[:SecureTokenLength])
	return secureToken, true
}

// Bytes returns the secret token as bytes.
func (secureToken SecureToken) Bytes() []byte {
	return secureToken[:]
}

// Expiry returns the SecureToken expiration time.
func (secureToken SecureToken) Expiry() time.Time {
	return time.UnixMilli(int64(binary.BigEndian.Uint64(secureToken[TokenLength:])))
}

// HMAC returns the HMAC part of the SecureToken.
func (secureToken SecureToken) HMAC() [SecureTokenHMACLength]byte {
	var result [SecureTokenHMACLength]byte
	copy(result[:], secureToken[TokenLength+SecureTokenTimeLength:])
	return result
}

// String returns the SecureToken as a string.
func (secureToken SecureToken) String() string {
	return base58.Encode(secureToken[:])
}

// Token returns the Token part of the SecureToken.
func (secureToken SecureToken) Token() Token {
	var result Token
	copy(result[:], secureToken[:])
	return result
}

// Verify verifies that the SecureToken has a valid HMAC and hasn't expired.
func (secureToken SecureToken) Verify(key []byte, now time.Time) error {
	if !secureToken.checkHMAC(key) {
		return ErrInvalid
	}

	if secureToken.Expiry().Before(now) {
		return ErrExpired
	}

	return nil
}

func (secureToken SecureToken) checkHMAC(key []byte) bool {
	expectedHMAC := secureToken.computeHMAC(key)
	actualHMAC := secureToken.HMAC()
	return hmac.Equal(actualHMAC[:], expectedHMAC[:])
}

func (secureToken SecureToken) computeHMAC(key []byte) (result [SecureTokenHMACLength]byte) {
	h := hmac.New(sha256.New, key)
	h.Write(secureToken[:TokenLength+SecureTokenTimeLength])
	copy(result[:], h.Sum(nil))
	return result
}
