package tokens

import (
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/chacha20poly1305"
)

func TestCodeEncryptor(t *testing.T) {
	cipherKey := make([]byte, chacha20poly1305.KeySize)
	_, _ = rand.Read(cipherKey)
	aead, err := chacha20poly1305.NewX(cipherKey)
	require.NoError(t, err)
	e := NewCodeEncryptor(aead)

	examplePayload := &CodePayload{
		RedirectURI:  "https://example.com/callback",
		Expiration:   time.Unix(1762887950, 0),
		Nonce:        "foo:bar:baz",
		SessionToken: "token",
	}

	t.Run("round trip", func(t *testing.T) {
		code := e.Encrypt(examplePayload, "https://example-client-id:1234")

		decrypted, err := e.Decrypt(code, "https://example-client-id:1234")
		require.NoError(t, err)
		assert.Equal(t, examplePayload, decrypted)
	})
	t.Run("mismatched client ID", func(t *testing.T) {
		code := e.Encrypt(examplePayload, "https://example-client-id:1234")

		_, err = e.Decrypt(code, "https://other-client-id:5678")
		require.ErrorContains(t, err, "message authentication failed")
	})
	t.Run("empty ciphertext", func(t *testing.T) {
		ad := []byte(adPrefixOIDCAuthorization + "https://example-client-id:1234")
		ciphertext := randomNonceAEAD{aead}.Encrypt(nil, ad)
		code := base64.RawURLEncoding.EncodeToString(ciphertext)

		_, err = e.Decrypt(code, "https://example-client-id:1234")
		require.ErrorContains(t, err, "format error")
	})
	t.Run("decode error", func(t *testing.T) {
		_, err = e.Decrypt("!invalid!", "https://other-client-id:5678")
		require.ErrorContains(t, err, "base64 decode")
	})
}

func TestAccessTokenEncryptor(t *testing.T) {
	cipherKey := make([]byte, chacha20poly1305.KeySize)
	_, _ = rand.Read(cipherKey)
	aead, err := chacha20poly1305.NewX(cipherKey)
	require.NoError(t, err)
	e := NewAccessTokenEncryptor(aead)

	t.Run("round trip", func(t *testing.T) {
		exampleToken := "foo-bar-baz"
		encrypted := e.Encrypt(exampleToken)

		decrypted, err := e.Decrypt(encrypted)
		require.NoError(t, err)
		assert.Equal(t, exampleToken, decrypted)
	})
	t.Run("decode error", func(t *testing.T) {
		_, err = e.Decrypt("!invalid!")
		require.ErrorContains(t, err, "base64 decode")
	})
	t.Run("decrypt error", func(t *testing.T) {
		_, err = e.Decrypt("AAAA")
		require.ErrorContains(t, err, "decrypt")
	})
}
