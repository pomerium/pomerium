package handlers_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/internal/deterministicecdsa"
	"github.com/pomerium/pomerium/internal/handlers"
	"github.com/pomerium/pomerium/pkg/cryptutil"
)

func TestJWKSHandler(t *testing.T) {
	t.Parallel()

	rnd := rand.New(rand.NewSource(1))
	signingKey1, err := deterministicecdsa.GenerateKey(elliptic.P256(), rnd)
	require.NoError(t, err)
	signingKey2, err := deterministicecdsa.GenerateKey(elliptic.P256(), rnd)
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
		r.Header.Set("Access-Control-Request-Method", "GET")
		handlers.JWKSHandler(nil).ServeHTTP(w, r)
		assert.Equal(t, http.StatusNoContent, w.Result().StatusCode)
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
