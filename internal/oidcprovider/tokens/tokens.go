// Package tokens contains methods for encrypting and decrypting access tokens,
// refresh tokens, state tokens, and authorization codes.
package tokens

import (
	"crypto/cipher"
	"crypto/ed25519"
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
	ClientKey    ed25519.PublicKey
	RequestUUID  string
	Expiration   time.Time
	OriginalCode string
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
		base64.RawStdEncoding.EncodeToString(p.ClientKey),
		url.QueryEscape(p.CallbackIP),
		p.RequestUUID,
		strconv.FormatInt(p.Expiration.Unix(), 10),
		p.OriginalCode,
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
	clientKey, err := base64.RawStdEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("invalid client key: %w", err)
	}
	callbackIP, err := url.QueryUnescape(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid callback IP address: %w", err)
	}
	exp, err := strconv.ParseInt(parts[3], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid expiration: %w", err)
	}
	return &CodePayload{
		ClientKey:    clientKey,
		CallbackIP:   callbackIP,
		RequestUUID:  parts[2],
		Expiration:   time.Unix(exp, 0),
		OriginalCode: parts[4],
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
	ClientKey ed25519.PublicKey
	Token     string
}

type RefreshTokenEncryptor struct {
	aead randomNonceAEAD
}

func NewRefreshTokenEncryptor(aead cipher.AEAD) *RefreshTokenEncryptor {
	return &RefreshTokenEncryptor{randomNonceAEAD{aead}}
}

// Encrypt encrypts a refresh token, returning a base64-encoded string.
func (e RefreshTokenEncryptor) Encrypt(p *RefreshPayload, clientID string) string {
	plaintext := strings.Join([]string{
		base64.RawStdEncoding.EncodeToString(p.ClientKey),
		p.Token,
	}, ":")
	ciphertext := e.aead.Encrypt([]byte(plaintext), []byte(adPrefixRefreshToken+clientID))
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
	parts := strings.SplitN(string(decrypted), ":", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("format error: want 2 parts, got %d", len(parts))
	}
	clientKey, err := base64.RawStdEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("invalid client key: %w", err)
	}
	return &RefreshPayload{
		ClientKey: clientKey,
		Token:     parts[1],
	}, nil
}

// StatePayload represents the data stored in a 'state' token.
type StatePayload struct {
	ClientID      string
	ClientKey     ed25519.PublicKey
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
		base64.RawStdEncoding.EncodeToString(p.ClientKey),
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
	clientKey, err := base64.RawStdEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid client key: %w", err)
	}
	exp, err := strconv.ParseInt(parts[3], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid expiration: %w", err)
	}
	p := StatePayload{
		ClientID:      clientID,
		ClientKey:     clientKey,
		RequestUUID:   parts[2],
		Expiration:    time.Unix(exp, 0),
		OriginalState: parts[4],
	}
	return &p, nil
}
