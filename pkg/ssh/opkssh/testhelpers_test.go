// Copyright (c) 2024 Pomerium, Inc.
// SPDX-License-Identifier: Apache-2.0

package opkssh

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/stretchr/testify/require"
)

// mockOIDC is the minimum OIDC discovery + JWKS surface needed to drive
// coreos/go-oidc's IDTokenVerifier from a unit test.
type mockOIDC struct {
	server   *httptest.Server
	signer   jose.Signer
	issuerID string
}

func startMockOIDC(t *testing.T) *mockOIDC {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	jwk := jose.JSONWebKey{Key: &priv.PublicKey, Algorithm: string(jose.ES256), Use: "sig"}
	thumb, err := jwk.Thumbprint(crypto.SHA256)
	require.NoError(t, err)
	jwk.KeyID = hex.EncodeToString(thumb)

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: priv},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", jwk.KeyID),
	)
	require.NoError(t, err)

	m := &mockOIDC{signer: signer}
	writeJSON := func(w http.ResponseWriter, v any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	}
	mux := http.NewServeMux()
	// The discovery handler closes over m.issuerID, which is only set below
	// after httptest.NewServer returns. That's fine: the handler only runs
	// when a client hits it, and by then the field is populated.
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{
			"issuer":                                m.issuerID,
			"jwks_uri":                              m.issuerID + "/.well-known/jwks.json",
			"id_token_signing_alg_values_supported": []string{"ES256"},
			"authorization_endpoint":                m.issuerID + "/auth",
			"response_types_supported":              []string{"id_token"},
			"subject_types_supported":               []string{"public"},
		})
	})
	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}})
	})

	m.server = httptest.NewServer(mux)
	m.issuerID = m.server.URL
	t.Cleanup(m.server.Close)
	return m
}

func (m *mockOIDC) issuer() string { return m.issuerID }

func (m *mockOIDC) mintIDToken(t *testing.T, audience, subject, email string) string {
	t.Helper()
	claims := struct {
		Iss   string           `json:"iss"`
		Aud   string           `json:"aud"`
		Sub   string           `json:"sub"`
		Email string           `json:"email"`
		Exp   *jwt.NumericDate `json:"exp"`
		Iat   *jwt.NumericDate `json:"iat"`
	}{
		Iss:   m.issuerID,
		Aud:   audience,
		Sub:   subject,
		Email: email,
		Exp:   jwt.NewNumericDate(time.Now().Add(time.Hour)),
		Iat:   jwt.NewNumericDate(time.Now()),
	}
	tok, err := jwt.Signed(m.signer).Claims(claims).CompactSerialize()
	require.NoError(t, err)
	return tok
}

// compactFromSingleOPJWS rewrites a standard JWS (protected.payload.sig)
// into the single-OP-segment opkssh compact form: payload:protected:sig.
func compactFromSingleOPJWS(t *testing.T, jws string) string {
	t.Helper()
	parts := strings.Split(jws, ".")
	require.Len(t, parts, 3)
	return parts[1] + ":" + parts[0] + ":" + parts[2]
}
