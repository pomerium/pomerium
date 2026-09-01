package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/config"
	oauth21proto "github.com/pomerium/pomerium/internal/oauth21/gen"
	rfc7591v1 "github.com/pomerium/pomerium/internal/rfc7591"
)

func TestClientMetadataJWKSURIWithoutPrivateKeyJWT(t *testing.T) {
	doc := &ClientIDMetadataDocument{
		ClientID:                "https://client.example.com/id",
		RedirectURIs:            []string{"https://client.example.com/cb"},
		TokenEndpointAuthMethod: "none",
		JWKSURI:                 "https://client.example.com/jwks",
	}
	assert.NoError(t, doc.Validate(),
		"a public client may publish a jwks_uri for purposes other than the token endpoint")
}

func TestClientMetadataPrivateKeyJWTStillRequiresJWKSURI(t *testing.T) {
	doc := &ClientIDMetadataDocument{
		ClientID:                "https://client.example.com/id",
		RedirectURIs:            []string{"https://client.example.com/cb"},
		TokenEndpointAuthMethod: rfc7591v1.TokenEndpointAuthMethodPrivateKeyJWT,
	}
	assert.ErrorContains(t, doc.Validate(), "requires jwks_uri")
}

func TestNegotiateSkipsPrivateKeyJWTWithoutJWKSURI(t *testing.T) {
	srv := &Handler{}
	doc := &ClientIDMetadataDocument{
		ClientID:                           "https://client.example.com/id",
		RedirectURIs:                       []string{"https://client.example.com/cb"},
		TokenEndpointAuthMethod:            "tls_client_auth",
		TokendEndpointAuthMethodsSupported: []string{"private_key_jwt", "none"},
	}
	require.NoError(t, srv.negotiateTokenEndpointAuthMethod(context.Background(), doc))
	assert.Equal(t, rfc7591v1.TokenEndpointAuthMethodNone, doc.TokenEndpointAuthMethod,
		"private_key_jwt is unusable without a jwks_uri, so negotiation must fall back to none")
	assert.NoError(t, doc.Validate())
}

func TestNegotiateStillPrefersPrivateKeyJWTWhenUsable(t *testing.T) {
	srv := &Handler{}
	doc := &ClientIDMetadataDocument{
		ClientID:                           "https://client.example.com/id",
		RedirectURIs:                       []string{"https://client.example.com/cb"},
		TokenEndpointAuthMethod:            "tls_client_auth",
		TokendEndpointAuthMethodsSupported: []string{"private_key_jwt", "none"},
		JWKSURI:                            "https://client.example.com/jwks",
	}
	require.NoError(t, srv.negotiateTokenEndpointAuthMethod(context.Background(), doc))
	assert.Equal(t, rfc7591v1.TokenEndpointAuthMethodPrivateKeyJWT, doc.TokenEndpointAuthMethod)
}

func countingJWKSHandler(t *testing.T, keys jose.JSONWebKeySet) (*http.Client, string, *atomic.Int64) {
	t.Helper()
	var n atomic.Int64
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(keys)
	}))
	t.Cleanup(server.Close)
	return server.Client(), server.URL + "/jwks.json", &n
}

func TestJWKSKeySetIsReusedAcrossRequests(t *testing.T) {
	clientID := "foo"
	key := newAssertionTestKey(t, jose.RS256, "key-1")
	aud := []string{"https://example.com/.pomerium/mcp/oauth/token"}
	client, jwksURI, count := countingJWKSHandler(t, key.jwks())
	reg := &rfc7591v1.ClientRegistration{
		ResponseMetadata: &rfc7591v1.Metadata{JwksUri: new(jwksURI)},
	}
	srv := &Handler{jwksFetcher: NewJWKSFetcher(client, allowAllDomainMatcher())}
	now := time.Now()
	for range 5 {
		assertion := key.sign(t, jwt.Claims{
			Issuer: clientID, Subject: clientID, Audience: aud,
			IssuedAt: jwt.NewNumericDate(now),
			Expiry:   jwt.NewNumericDate(now.Add(2 * time.Minute)),
		})
		req := tokenRequest(rfc7591v1.GrantTypesJWTBearer, clientID, assertion)
		require.NoError(t, srv.verifyClientAssertion(t.Context(), req, reg, aud))
	}
	assert.Equal(t, int64(1), count.Load(),
		"the jwks_uri is client-controlled; it must not be re-fetched per token request")
}

func TestClientAssertionLifetimeIsBounded(t *testing.T) {
	clientID := "foo"
	key := newAssertionTestKey(t, jose.RS256, "key-1")
	aud := []string{"https://example.com/.pomerium/mcp/oauth/token"}
	client, jwksURI := jwksHandler(t, key.jwks())
	reg := &rfc7591v1.ClientRegistration{
		ResponseMetadata: &rfc7591v1.Metadata{JwksUri: new(jwksURI)},
	}
	srv := &Handler{jwksFetcher: NewJWKSFetcher(client, allowAllDomainMatcher())}
	now := time.Now()

	sign := func(d time.Duration) *oauth21proto.TokenRequest {
		return tokenRequest(rfc7591v1.GrantTypesJWTBearer, clientID, key.sign(t, jwt.Claims{
			Issuer: clientID, Subject: clientID, Audience: aud,
			IssuedAt: jwt.NewNumericDate(now), Expiry: jwt.NewNumericDate(now.Add(d)),
		}))
	}

	assert.NoError(t, srv.verifyClientAssertion(t.Context(), sign(2*time.Minute), reg, aud))
	assert.ErrorContains(t,
		srv.verifyClientAssertion(t.Context(), sign(10*365*24*time.Hour), reg, aud),
		"expires more than",
		"an assertion with an unbounded lifetime is a durable credential, not a one-shot proof")
}

func TestTokenEndpointAudiencesRejectsUnconfiguredHost(t *testing.T) {
	srv := &Handler{
		prefix: "/.pomerium/mcp/oauth",
		hosts:  NewHostInfo(&config.Config{Options: config.NewDefaultOptions()}, http.DefaultClient),
	}
	r := httptest.NewRequest(http.MethodPost, "/.pomerium/mcp/oauth/token", nil)
	r.Host = "evil-as.example"
	assert.Empty(t, srv.tokenEndpointAudiences(r),
		"the /.pomerium/ prefix is served from Envoy's catch-all vhost, so Host must be validated")
}
