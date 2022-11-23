package handlers_test

import (
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/internal/handlers"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	"github.com/pomerium/pomerium/pkg/hpke"
)

func TestJWKSHandler(t *testing.T) {
	t.Parallel()

	signingKey, err := cryptutil.NewSigningKey()
	require.NoError(t, err)

	rawSigningKey, err := cryptutil.EncodePrivateKey(signingKey)
	require.NoError(t, err)

	jwkSigningKey, err := cryptutil.PublicJWKFromBytes(rawSigningKey)
	require.NoError(t, err)

	hpkePrivateKey, err := hpke.GeneratePrivateKey()
	require.NoError(t, err)

	t.Run("cors", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodOptions, "/", nil)
		r.Header.Set("Origin", "https://www.example.com")
		r.Header.Set("Access-Control-Request-Method", "GET")
		handlers.JWKSHandler("", hpkePrivateKey.PublicKey()).ServeHTTP(w, r)
		assert.Equal(t, http.StatusNoContent, w.Result().StatusCode)
	})
	t.Run("keys", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		handlers.JWKSHandler(base64.StdEncoding.EncodeToString(rawSigningKey), hpkePrivateKey.PublicKey()).ServeHTTP(w, r)

		var expect any = map[string]any{
			"keys": []any{
				map[string]any{
					"kty": "EC",
					"kid": jwkSigningKey.KeyID,
					"crv": "P-256",
					"alg": "ES256",
					"use": "sig",
					"x":   base64.RawURLEncoding.EncodeToString(jwkSigningKey.Key.(*ecdsa.PublicKey).X.Bytes()),
					"y":   base64.RawURLEncoding.EncodeToString(jwkSigningKey.Key.(*ecdsa.PublicKey).Y.Bytes()),
				},
				map[string]any{
					"kty": "OKP",
					"kid": "pomerium/hpke",
					"crv": "X25519",
					"x":   hpkePrivateKey.PublicKey().String(),
				},
			},
		}
		var actual any
		err := json.Unmarshal(w.Body.Bytes(), &actual)
		assert.NoError(t, err)
		assert.Equal(t, expect, actual)
	})
}
