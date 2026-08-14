package tokens

import (
	"crypto/ed25519"
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
		ClientKey:    ed25519.PublicKey("12345678901234567890123456789012"),
		RequestUUID:  "195c073b-e369-4c8a-a429-85fa3a0c3d74",
		Expiration:   time.Unix(1762887950, 0),
		OriginalCode: "original-code",
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

func TestRefreshTokenEncryptor(t *testing.T) {
	cipherKey := make([]byte, chacha20poly1305.KeySize)
	_, _ = rand.Read(cipherKey)
	aead, err := chacha20poly1305.NewX(cipherKey)
	require.NoError(t, err)
	e := NewRefreshTokenEncryptor(aead)

	examplePayload := &RefreshPayload{
		ClientKey: ed25519.PublicKey("12345678901234567890123456789012"),
		Token:     "foo-bar-baz",
	}

	t.Run("round trip", func(t *testing.T) {
		encrypted := e.Encrypt(examplePayload, "https://example-client-id:1234")

		decrypted, err := e.Decrypt(encrypted, "https://example-client-id:1234")
		require.NoError(t, err)
		assert.Equal(t, examplePayload, decrypted)
	})
	t.Run("mismatched client ID", func(t *testing.T) {
		encrypted := e.Encrypt(examplePayload, "https://example-client-id:1234")

		_, err = e.Decrypt(encrypted, "https://other-client-id:5678")
		require.ErrorContains(t, err, "message authentication failed")
	})
	t.Run("decode error", func(t *testing.T) {
		_, err = e.Decrypt("!invalid!", "https://example-client-id:1234")
		require.ErrorContains(t, err, "base64 decode")
	})
}

func TestStateEncryptor(t *testing.T) {
	cipherKey := make([]byte, chacha20poly1305.KeySize)
	_, _ = rand.Read(cipherKey)
	aead, err := chacha20poly1305.NewX(cipherKey)
	require.NoError(t, err)
	e := NewStateEncryptor(aead)

	t.Run("round trip", func(t *testing.T) {
		p := &StatePayload{
			ClientID:      "https://client.example.com:1234/foo/bar?baz",
			ClientKey:     ed25519.PublicKey("12345678901234567890123456789012"),
			RequestUUID:   "195c073b-e369-4c8a-a429-85fa3a0c3d74",
			Expiration:    time.Unix(1762887950, 0),
			OriginalState: "original:state",
		}
		encrypted := e.Encrypt(p)

		decrypted, err := e.Decrypt(encrypted)
		require.NoError(t, err)
		assert.Equal(t, p, decrypted)
	})
	t.Run("decrypt error", func(t *testing.T) {
		_, err = e.Decrypt("AAAA")
		require.ErrorContains(t, err, "decrypt")
	})
	t.Run("decode error", func(t *testing.T) {
		_, err = e.Decrypt("!invalid!")
		require.ErrorContains(t, err, "base64 decode")
	})
}
