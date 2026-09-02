package mcp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/internal/oauth21"
	rfc7591v1 "github.com/pomerium/pomerium/internal/rfc7591"
)

// The RFC 7523 Section 2.1 grant type URN is a different string, for a
// different parameter, than the Section 2.2 client assertion type URN.
func TestClientAssertionTypeIsTheRFC7523Value(t *testing.T) {
	clientID := "foo"
	key := newAssertionTestKey(t, jose.RS256, "key-1")
	aud := []string{"https://example.com/.pomerium/mcp/oauth/token"}
	client, jwksURI := jwksHandler(t, key.jwks())
	reg := &rfc7591v1.ClientRegistration{
		ResponseMetadata: &rfc7591v1.Metadata{JwksUri: new(jwksURI)},
	}
	srv := &Handler{jwksFetcher: NewJWKSFetcher(client, allowAllDomainMatcher())}

	now := time.Now()
	assertion := key.sign(t, jwt.Claims{
		Issuer: clientID, Subject: clientID, Audience: aud,
		IssuedAt: jwt.NewNumericDate(now), Expiry: jwt.NewNumericDate(now.Add(2 * time.Minute)),
	})

	assert.NoError(t,
		srv.verifyClientAssertion(t.Context(),
			tokenRequest(oauth21.ClientAssertionTypeJWTBearer, clientID, assertion), reg, aud),
		"a conformant client sends the RFC 7523 Section 2.2 client-assertion-type URN")

	assert.Error(t,
		srv.verifyClientAssertion(t.Context(),
			tokenRequest(rfc7591v1.GrantTypesJWTBearer, clientID, assertion), reg, aud),
		"the Section 2.1 grant-type URN is not a valid client_assertion_type")
}

// The CIMD draft forbids client_secret_basic, so RFC 7591's "omitted means
// client_secret_basic" default cannot apply to a metadata document. Apart from
// the omission this is the MCP specification's own example document.
func TestCIMDWithoutTokenEndpointAuthMethod(t *testing.T) {
	var clientID string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"client_id":      clientID,
			"client_name":    "Example MCP Client",
			"redirect_uris":  []string{"http://127.0.0.1:3000/callback"},
			"grant_types":    []string{"authorization_code"},
			"response_types": []string{"code"},
			// token_endpoint_auth_method deliberately omitted
		})
	}))
	t.Cleanup(server.Close)
	clientID = server.URL + "/oauth/client-metadata.json"

	srv := &Handler{
		clientMetadataFetcher: NewClientMetadataFetcher(server.Client(), allowAllDomainMatcher()),
	}
	reg, err := srv.getOrFetchClient(t.Context(), clientID)
	require.NoError(t, err, "a client that omits token_endpoint_auth_method must not be rejected")
	assert.Equal(t, rfc7591v1.TokenEndpointAuthMethodNone,
		reg.GetResponseMetadata().GetTokenEndpointAuthMethod())
}

// The CIMD path converts to an rfc7591v1.Metadata, so every method it can
// negotiate has to be a value that message accepts.
func TestMetadataAcceptsEveryNegotiableAuthMethod(t *testing.T) {
	for _, method := range supportedTokenAuthMethodsForCIMD {
		t.Run(method, func(t *testing.T) {
			md := &rfc7591v1.Metadata{
				RedirectUris:            []string{"https://client.example.com/callback"},
				TokenEndpointAuthMethod: &method,
				JwksUri:                 new("https://client.example.com/jwks.json"),
			}
			assert.NoError(t, md.Validate())
		})
	}
}
