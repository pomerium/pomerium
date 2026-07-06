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
// Note that authorization codes and refresh tokens are scoped to a specific
// client ID.
const (
	adAccessToken = "access-token"
	adState       = "state"

	adPrefixOIDCAuthorization = "oidc-authorization:"
	adPrefixRefreshToken      = "refresh-token:"
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

// RefreshPayload represents the data stored in a refresh token.
type RefreshPayload struct {
	Token string
}

type RefreshTokenEncryptor struct {
	aead randomNonceAEAD
}

func NewRefreshTokenEncryptor(aead cipher.AEAD) *RefreshTokenEncryptor {
	return &RefreshTokenEncryptor{randomNonceAEAD{aead}}
}

// Encrypt encrypts a refresh token, returning a base64-encoded string.
func (e RefreshTokenEncryptor) Encrypt(p *RefreshPayload, clientID string) string {
	ciphertext := e.aead.Encrypt([]byte(p.Token), []byte(adPrefixRefreshToken+clientID))
	return base64.RawStdEncoding.EncodeToString(ciphertext)
}

// Decrypt decrypts a refresh token, returning the payload data or an error.
func (e RefreshTokenEncryptor) Decrypt(token, clientID string) (*RefreshPayload, error) {
	ciphertext, err := base64.RawStdEncoding.DecodeString(token)
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
	}
	decrypted, err := e.aead.Decrypt(ciphertext, []byte(adPrefixRefreshToken+clientID))
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}
	return &RefreshPayload{
		Token: string(decrypted),
	}, nil
}

// StatePayload represents the data stored in a 'state' token.
type StatePayload struct {
	ClientID      string
	RedirectPath  string
	RequestUUID   string
	Expiration    time.Time
	OriginalState string
}

type StateEncryptor struct {
	aead randomNonceAEAD
}

func NewStateEncryptor(aead cipher.AEAD) *StateEncryptor {
	return &StateEncryptor{randomNonceAEAD{aead}}
}

// Encrypt encrypts a state token, returning a base64-encoded string.
func (e StateEncryptor) Encrypt(p *StatePayload) string {
	plaintext := strings.Join([]string{
		url.QueryEscape(p.ClientID),
		url.QueryEscape(p.RedirectPath),
		p.RequestUUID,
		strconv.FormatInt(p.Expiration.Unix(), 10),
		p.OriginalState,
	}, ":")
	ciphertext := e.aead.Encrypt([]byte(plaintext), []byte(adState))
	return base64.RawURLEncoding.EncodeToString(ciphertext)
}

// Decrypt decrypts a state token, returning the token payload or an error.
func (e StateEncryptor) Decrypt(token string) (*StatePayload, error) {
	ciphertext, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
	}
	decrypted, err := e.aead.Decrypt(ciphertext, []byte(adState))
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}
	parts := strings.SplitN(string(decrypted), ":", 5)
	if len(parts) != 5 {
		return nil, fmt.Errorf("format error: want 5 parts, got %d", len(parts))
	}
	clientID, err := url.QueryUnescape(parts[0])
	if err != nil {
		return nil, fmt.Errorf("invalid client ID: %w", err)
	}
	redirectPath, err := url.QueryUnescape(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid redirect path: %w", err)
	}
	exp, err := strconv.ParseInt(parts[3], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid expiration: %w", err)
	}
	p := StatePayload{
		ClientID:      clientID,
		RedirectPath:  redirectPath,
		RequestUUID:   parts[2],
		Expiration:    time.Unix(exp, 0),
		OriginalState: parts[4],
	}
	return &p, nil
}
