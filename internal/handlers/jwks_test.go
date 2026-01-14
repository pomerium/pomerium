package handlers_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"testing"

	"filippo.io/keygen"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/internal/handlers"
	"github.com/pomerium/pomerium/pkg/cryptutil"
)

const invalidKey = `-----BEGIN EC PRIVATE KEY-----
foobar==
-----END EC PRIVATE KEY-----`

func TestJWKSHandler(t *testing.T) {
	t.Parallel()

	rnd := rand.New(rand.NewSource(1))
	signingKey1, err := keygen.ECDSALegacy(elliptic.P256(), rnd)
	require.NoError(t, err)
	signingKey2, err := keygen.ECDSALegacy(elliptic.P256(), rnd)
	require.NoError(t, err)

	rawSigningKey1, err := cryptutil.EncodePrivateKey(signingKey1)
	require.NoError(t, err)
	rawSigningKey2, err := cryptutil.EncodePrivateKey(signingKey2)
	require.NoError(t, err)

	jwkSigningKey1, err := cryptutil.PublicJWKFromBytes(rawSigningKey1)
	require.NoError(t, err)
	jwkSigningKey2, err := cryptutil.PublicJWKFromBytes(rawSigningKey2)
	require.NoError(t, err)

	t.Run("cors", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodOptions, "/", nil)
		r.Header.Set("Origin", "https://www.example.com")
		r.Header.Set("Access-Control-Request-Method", http.MethodGet)
		handlers.JWKSHandler(nil).ServeHTTP(w, r)
		assert.Equal(t, http.StatusNoContent, w.Result().StatusCode)
	})
	t.Run("empty key set", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		handlers.JWKSHandler(nil).ServeHTTP(w, r)
		res := w.Result()
		assert.Equal(t, http.StatusOK, res.StatusCode)
		b, err := io.ReadAll(res.Body)
		require.NoError(t, err)
		assert.JSONEq(t, `{"keys":null}`, string(b))
	})
	t.Run("invalid", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		handlers.JWKSHandler([]byte(invalidKey)).ServeHTTP(w, r)
		res := w.Result()
		assert.Equal(t, http.StatusInternalServerError, res.StatusCode)
	})
	t.Run("keys", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		handlers.JWKSHandler(append(rawSigningKey1, rawSigningKey2...)).ServeHTTP(w, r)

		var expect any = map[string]any{
			"keys": []any{
				map[string]any{
					"kty": "EC",
					"kid": jwkSigningKey1.KeyID,
					"crv": "P-256",
					"alg": "ES256",
					"use": "sig",
					"x":   base64.RawURLEncoding.EncodeToString(jwkSigningKey1.Key.(*ecdsa.PublicKey).X.Bytes()),
					"y":   base64.RawURLEncoding.EncodeToString(jwkSigningKey1.Key.(*ecdsa.PublicKey).Y.Bytes()),
				},
				map[string]any{
					"kty": "EC",
					"kid": jwkSigningKey2.KeyID,
					"crv": "P-256",
					"alg": "ES256",
					"use": "sig",
					"x":   base64.RawURLEncoding.EncodeToString(jwkSigningKey2.Key.(*ecdsa.PublicKey).X.Bytes()),
					"y":   base64.RawURLEncoding.EncodeToString(jwkSigningKey2.Key.(*ecdsa.PublicKey).Y.Bytes()),
				},
			},
		}
		var actual any
		err := json.Unmarshal(w.Body.Bytes(), &actual)
		assert.NoError(t, err)
		assert.Equal(t, expect, actual)
	})
}

func BenchmarkJWKSHandler(b *testing.B) {
	key, err := cryptutil.NewSigningKey()
	require.NoError(b, err)
	pem, err := cryptutil.EncodePrivateKey(key)
	require.NoError(b, err)
	h := handlers.JWKSHandler(pem)

	for b.Loop() {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/jwks.json", nil)
		h.ServeHTTP(w, r)
	}
}
