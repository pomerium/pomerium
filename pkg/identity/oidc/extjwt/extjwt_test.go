package extjwt_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/internal/testutil/mockidp"
	"github.com/pomerium/pomerium/pkg/identity/oidc/extjwt"
)

// rs256issuer is a mockidp-based test issuer (ES256 signing key, since
// mockidp uses ES256). We use it for the RS256 vs ES256 alg-allowlist test.

// newTestIssuer returns (issuer URL, mockidp instance).
func newTestIssuer(t *testing.T) (string, *mockidp.IDP) {
	t.Helper()
	idp := mockidp.New(mockidp.Config{})
	return idp.Start(t), idp
}

func newProvider(t *testing.T, issuer string, algs []string) *extjwt.Provider {
	t.Helper()
	if algs == nil {
		algs = []string{"ES256"} // mockidp uses ES256
	}
	p, err := extjwt.New(extjwt.Config{
		Issuer:        issuer,
		SupportedAlgs: algs,
	})
	require.NoError(t, err)
	return p
}

func stdClaims(issuer, sub, aud string, now time.Time) map[string]any {
	return map[string]any{
		"iss": issuer,
		"sub": sub,
		"aud": []string{aud},
		"exp": now.Add(time.Hour).Unix(),
		"iat": now.Unix(),
		"nbf": now.Unix(),
	}
}

func TestVerify_HappyPath(t *testing.T) {
	t.Parallel()
	issuer, idp := newTestIssuer(t)
	p := newProvider(t, issuer, nil)
	tok := idp.SignJWT(stdClaims(issuer, "system:serviceaccount:ns:sa", "pomerium.example.com", time.Now()))
	claims, err := p.Verify(t.Context(), tok, []string{"pomerium.example.com"})
	require.NoError(t, err)
	assert.Equal(t, "system:serviceaccount:ns:sa", claims["sub"])
}

func TestVerify_AudienceMismatch(t *testing.T) {
	t.Parallel()
	issuer, idp := newTestIssuer(t)
	p := newProvider(t, issuer, nil)
	tok := idp.SignJWT(stdClaims(issuer, "sub", "other.example.com", time.Now()))
	_, err := p.Verify(t.Context(), tok, []string{"pomerium.example.com"})
	assert.ErrorIs(t, err, extjwt.ErrAudienceMismatch)
}

func TestVerify_EmptyAudiencesIsConfigError(t *testing.T) {
	t.Parallel()
	// The plan forbids empty audience allowlists; the verifier must
	// surface this as a config error rather than silently accept any aud.
	issuer, idp := newTestIssuer(t)
	p := newProvider(t, issuer, nil)
	tok := idp.SignJWT(stdClaims(issuer, "sub", "aud", time.Now()))
	_, err := p.Verify(t.Context(), tok, nil)
	assert.ErrorIs(t, err, extjwt.ErrEmptyAudiences)
	_, err = p.Verify(t.Context(), tok, []string{})
	assert.ErrorIs(t, err, extjwt.ErrEmptyAudiences)
}

func TestVerify_Expired(t *testing.T) {
	t.Parallel()
	issuer, idp := newTestIssuer(t)
	p := newProvider(t, issuer, nil)
	tok := idp.SignJWT(map[string]any{
		"iss": issuer,
		"sub": "sub",
		"aud": []string{"aud"},
		"exp": time.Now().Add(-time.Hour).Unix(),
		"iat": time.Now().Add(-2 * time.Hour).Unix(),
		"nbf": time.Now().Add(-2 * time.Hour).Unix(),
	})
	_, err := p.Verify(t.Context(), tok, []string{"aud"})
	require.Error(t, err)
}

func TestVerify_FutureNbf(t *testing.T) {
	t.Parallel()
	issuer, idp := newTestIssuer(t)
	p := newProvider(t, issuer, nil)
	tok := idp.SignJWT(map[string]any{
		"iss": issuer,
		"sub": "sub",
		"aud": []string{"aud"},
		"nbf": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(2 * time.Hour).Unix(),
	})
	_, err := p.Verify(t.Context(), tok, []string{"aud"})
	require.Error(t, err)
}

func TestVerify_IssuerMismatch(t *testing.T) {
	t.Parallel()
	issuer, idp := newTestIssuer(t)
	p := newProvider(t, issuer, nil)
	tok := idp.SignJWT(stdClaims("https://attacker.example.com", "sub", "aud", time.Now()))
	_, err := p.Verify(t.Context(), tok, []string{"aud"})
	require.Error(t, err)
}

func TestVerify_GarbageToken(t *testing.T) {
	t.Parallel()
	issuer, _ := newTestIssuer(t)
	p := newProvider(t, issuer, nil)
	_, err := p.Verify(t.Context(), "not-a-jwt", []string{"aud"})
	require.Error(t, err)
}

func TestNew_MissingIssuer(t *testing.T) {
	t.Parallel()
	_, err := extjwt.New(extjwt.Config{SupportedAlgs: []string{"RS256"}})
	assert.ErrorIs(t, err, extjwt.ErrMissingIssuer)
}

func TestNew_EmptyAlgs(t *testing.T) {
	t.Parallel()
	_, err := extjwt.New(extjwt.Config{Issuer: "https://example.com"})
	require.Error(t, err)
}

// TestVerify_AlgAllowlist_ES256_OnJWKSPath verifies the review #5 fix:
// when using the explicit JWKS-URL path, an ES256 token must be accepted if
// "ES256" is in SupportedAlgs (go-oidc would otherwise default to RS256-only
// and silently reject it).
func TestVerify_AlgAllowlist_ES256_OnJWKSPath(t *testing.T) {
	t.Parallel()

	// Custom JWKS server hosting an ES256 key.
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	jwk := jose.JSONWebKey{
		Key:       &priv.PublicKey,
		Algorithm: "ES256",
		Use:       "sig",
	}
	thumb, _ := jwk.Thumbprint(crypto.SHA256)
	jwk.KeyID = hex.EncodeToString(thumb)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(&jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}})
	}))
	t.Cleanup(srv.Close)

	issuer := "https://my-issuer.example.com"

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: priv}, (&jose.SignerOptions{}).WithType("JWT"))
	require.NoError(t, err)
	tok, err := jwt.Signed(signer).Claims(stdClaims(issuer, "sub", "aud", time.Now())).CompactSerialize()
	require.NoError(t, err)

	t.Run("default ES256 is accepted", func(t *testing.T) {
		// SupportedAlgs is required, and our default explicitly includes ES256.
		p, err := extjwt.New(extjwt.Config{
			Issuer:        issuer,
			JWKSURL:       srv.URL,
			SupportedAlgs: []string{"RS256", "ES256", "EdDSA"},
		})
		require.NoError(t, err)
		claims, err := p.Verify(t.Context(), tok, []string{"aud"})
		require.NoError(t, err)
		assert.Equal(t, "sub", claims["sub"])
	})

	t.Run("ES256 rejected when allowlist is RS256-only", func(t *testing.T) {
		p, err := extjwt.New(extjwt.Config{
			Issuer:        issuer,
			JWKSURL:       srv.URL,
			SupportedAlgs: []string{"RS256"},
		})
		require.NoError(t, err)
		_, err = p.Verify(context.Background(), tok, []string{"aud"})
		require.Error(t, err)
	})
}
