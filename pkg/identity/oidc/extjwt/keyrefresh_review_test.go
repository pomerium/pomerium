package extjwt_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/pkg/identity/oidc/extjwt"
)

// rotatableJWKS is a JWKS server whose published key can be swapped at will,
// so a test can force go-oidc's RemoteKeySet into a key-cache miss (which is
// the only path that triggers a background JWKS re-fetch).
type rotatableJWKS struct {
	mu     sync.RWMutex
	priv   *ecdsa.PrivateKey
	kid    string
	server *httptest.Server
}

func newRotatableJWKS(t *testing.T) *rotatableJWKS {
	t.Helper()
	r := &rotatableJWKS{}
	r.rotate(t, "keyA")
	r.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		r.mu.RLock()
		defer r.mu.RUnlock()
		jwk := jose.JSONWebKey{Key: &r.priv.PublicKey, KeyID: r.kid, Algorithm: "ES256", Use: "sig"}
		_ = json.NewEncoder(w).Encode(&jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}})
	}))
	t.Cleanup(r.server.Close)
	return r
}

// rotate swaps in a brand-new signing key published under the given kid.
func (r *rotatableJWKS) rotate(t *testing.T, kid string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	r.mu.Lock()
	r.priv = priv
	r.kid = kid
	r.mu.Unlock()
}

// sign mints a token with the CURRENT key, embedding its kid in the JWS header
// so RemoteKeySet knows which key to look for (and detects a cache miss).
func (r *rotatableJWKS) sign(t *testing.T, issuer, sub, aud string) string {
	t.Helper()
	r.mu.RLock()
	defer r.mu.RUnlock()
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: jose.JSONWebKey{Key: r.priv, KeyID: r.kid, Algorithm: "ES256"}},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	require.NoError(t, err)
	now := time.Now()
	tok, err := jwt.Signed(signer).Claims(map[string]any{
		"iss": issuer, "sub": sub, "aud": []string{aud},
		"exp": now.Add(time.Hour).Unix(), "iat": now.Unix(), "nbf": now.Unix(),
	}).CompactSerialize()
	require.NoError(t, err)
	return tok
}

// TestProvider_KeyRefreshAfterInitContextCancelled is the adversarial red test
// proposed in the Greptile PR review (finding #2): it claims that because
// getVerifier builds the RemoteKeySet with the FIRST inbound request's context,
// cancelling that context permanently breaks future JWKS key refreshes.
//
// It does NOT break: go-oidc v3.17.0 stores the constructor context as
// `context.WithoutCancel(ctx)` (jwks.go:71) — cancellation is stripped, only
// the values (the injected HTTP client) are retained. This test proves the
// finding is a FALSE POSITIVE by driving exactly the scenario the review
// describes and asserting the second verify SUCCEEDS.
func TestProvider_KeyRefreshAfterInitContextCancelled(t *testing.T) {
	t.Parallel()

	jwks := newRotatableJWKS(t)
	const issuer = "https://issuer.review.example.com"

	p, err := extjwt.New(extjwt.Config{
		Issuer:        issuer,
		JWKSURL:       jwks.server.URL,
		SupportedAlgs: []string{"ES256"},
	})
	require.NoError(t, err)

	// First verify with a cancellable context — this is the request whose
	// context getVerifier captures into the RemoteKeySet.
	ctx1, cancel1 := context.WithCancel(context.Background())
	tok1 := jwks.sign(t, issuer, "sub1", "aud")
	_, err = p.Verify(ctx1, tok1, []string{"aud"})
	require.NoError(t, err, "first verify must succeed and populate the key cache")

	// The request completes: its context is cancelled.
	cancel1()

	// Rotate the issuer's signing key. The next token carries a new kid that
	// is NOT in the cache, forcing RemoteKeySet.updateKeys() to hit the network
	// again — the exact path the review says uses the cancelled context.
	jwks.rotate(t, "keyB")
	tok2 := jwks.sign(t, issuer, "sub2", "aud")

	// Second verify with a FRESH context. If the finding were correct, the
	// background key-refresh would use the cancelled ctx1 and fail with
	// "context canceled". WithoutCancel means it does not.
	claims, err := p.Verify(context.Background(), tok2, []string{"aud"})
	require.NoError(t, err, "key refresh after init-context cancellation must still succeed (finding #2 is a false positive)")
	assert.Equal(t, "sub2", claims["sub"])
}
