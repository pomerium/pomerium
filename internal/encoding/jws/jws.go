// Package jws represents content secured with digitalsignatures
// using JSON-based data structures as specified by rfc7515
package jws

import (
	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"

	"github.com/pomerium/pomerium/internal/encoding"
)

// JSONWebSigner is the struct representing a signed JWT.
// https://tools.ietf.org/html/rfc7519
type JSONWebSigner struct {
	Signer jose.Signer

	key interface{}
}

// NewHS256Signer creates a SHA256 JWT signer from a 32 byte key.
func NewHS256Signer(key []byte) (encoding.MarshalUnmarshaler, error) {
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: key},
		(&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		return nil, err
	}
	return &JSONWebSigner{Signer: sig, key: key}, nil
}

// Marshal signs, and serializes a JWT.
func (c *JSONWebSigner) Marshal(x interface{}) ([]byte, error) {
	s, err := jwt.Signed(c.Signer).Claims(x).CompactSerialize()
	return []byte(s), err
}

// Unmarshal parses and validates a signed JWT.
func (c *JSONWebSigner) Unmarshal(value []byte, s interface{}) error {
	tok, err := jwt.ParseSigned(string(value))
	if err != nil {
		return err
	}
	return tok.Claims(c.key, s)
}
