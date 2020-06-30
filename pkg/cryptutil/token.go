package cryptutil

import (
	"github.com/btcsuite/btcutil/base58"
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
	result := base58.Decode(rawstr)
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
	result := base58.Decode(rawstr)
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
