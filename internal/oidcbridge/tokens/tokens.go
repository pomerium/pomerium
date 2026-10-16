// Package tokens contains methods for encrypting and decrypting access tokens,
// refresh tokens, state tokens, and authorization codes.
package tokens

import (
	"crypto/cipher"
	"encoding/base64"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// "Additional data" constants for AEAD cipher. These are to ensure that a value
// encrypted for one context cannot be decrypted in another context.
//
// Note that authorization codes are scoped to a specific client ID.
const (
	adAccessToken = "access-token"

	adPrefixOIDCAuthorization = "oidc-authorization:"
)

// CodePayload represents the data stored in an authorization code.
type CodePayload struct {
	RedirectURI       string
	Expiration        time.Time
	S256CodeChallenge string
	Nonce             string
	SessionToken      string
}

type CodeEncryptor struct {
	aead randomNonceAEAD
}

func NewCodeEncryptor(aead cipher.AEAD) *CodeEncryptor {
	return &CodeEncryptor{randomNonceAEAD{aead}}
}

// Encrypt encrypts a [CodePayload], returning an opaque authorization code as a
// base64-encoded string.
func (e CodeEncryptor) Encrypt(p *CodePayload, clientID string) string {
	plaintext := strings.Join([]string{
		url.QueryEscape(p.RedirectURI),
		strconv.FormatInt(p.Expiration.Unix(), 10),
		p.S256CodeChallenge,
		url.QueryEscape(p.Nonce),
		p.SessionToken,
	}, ":")
	ciphertext := e.aead.Encrypt([]byte(plaintext), []byte(adPrefixOIDCAuthorization+clientID))
	return base64.RawURLEncoding.EncodeToString(ciphertext)
}

// Decrypt decrypts an authorization code, returning a [CodePayload] or an error.
func (e CodeEncryptor) Decrypt(code, clientID string) (*CodePayload, error) {
	ciphertext, err := base64.RawURLEncoding.DecodeString(code)
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
	}
	decrypted, err := e.aead.Decrypt(ciphertext, []byte(adPrefixOIDCAuthorization+clientID))
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}
	parts := strings.SplitN(string(decrypted), ":", 5)
	if len(parts) != 5 {
		return nil, fmt.Errorf("format error: want 5 parts, got %d", len(parts))
	}
	redirectURI, err := url.QueryUnescape(parts[0])
	if err != nil {
		return nil, fmt.Errorf("invalid redirect URI: %w", err)
	}
	exp, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid expiration: %w", err)
	}
	nonce, err := url.QueryUnescape(parts[3])
	if err != nil {
		return nil, fmt.Errorf("invalid redirect URI: %w", err)
	}
	return &CodePayload{
		RedirectURI:       redirectURI,
		Expiration:        time.Unix(exp, 0),
		S256CodeChallenge: parts[2],
		Nonce:             nonce,
		SessionToken:      parts[4],
	}, nil
}

type AccessTokenEncryptor struct {
	aead randomNonceAEAD
}

func NewAccessTokenEncryptor(aead cipher.AEAD) *AccessTokenEncryptor {
	return &AccessTokenEncryptor{randomNonceAEAD{aead}}
}

// Encrypt encrypts an access token, returning a base64-encoded string.
func (e AccessTokenEncryptor) Encrypt(token string) string {
	ciphertext := e.aead.Encrypt([]byte(token), []byte(adAccessToken))
	return base64.RawStdEncoding.EncodeToString(ciphertext)
}

// Decrypt decrypts an access token, returning the token or an error.
func (e AccessTokenEncryptor) Decrypt(token string) (string, error) {
	ciphertext, err := base64.RawStdEncoding.DecodeString(token)
	if err != nil {
		return "", fmt.Errorf("base64 decode: %w", err)
	}
	decrypted, err := e.aead.Decrypt(ciphertext, []byte(adAccessToken))
	if err != nil {
		return "", fmt.Errorf("decrypt: %w", err)
	}
	return string(decrypted), nil
}
