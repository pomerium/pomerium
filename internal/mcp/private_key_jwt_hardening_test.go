package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/oauth21"
	oauth21proto "github.com/pomerium/pomerium/internal/oauth21/gen"
	rfc7591v1 "github.com/pomerium/pomerium/internal/rfc7591"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	"github.com/pomerium/pomerium/pkg/grpc/session"
)

func countingJWKSHandler(t *testing.T, keys jose.JSONWebKeySet) (*http.Client, string, *atomic.Int64) {
	t.Helper()
	n := new(atomic.Int64)
	client, uri := jwksHandlerFunc(t, keys, func() { n.Add(1) })
	return client, uri, n
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
		req := tokenRequest(oauth21.ClientAssertionTypeJWTBearer, clientID, assertion)
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
		return tokenRequest(oauth21.ClientAssertionTypeJWTBearer, clientID, key.sign(t, jwt.Claims{
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

// cimdHandler serves doc as a client ID metadata document, filling in the
// client_id the draft requires it to match, and returns a Handler that fetches
// from it along with that client_id.
func cimdHandler(t *testing.T, doc map[string]any) (srv *Handler, clientID string) {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doc)
	}))
	t.Cleanup(server.Close)
	clientID = server.URL + "/oauth/client.json"
	doc["client_id"] = clientID
	return &Handler{
		clientMetadataFetcher: NewClientMetadataFetcher(server.Client(), allowAllDomainMatcher()),
	}, clientID
}

// getOrFetchClient is the only production caller of Validate; without this the
// call can be deleted outright and the package suite still passes.
func TestGetOrFetchClientValidatesFetchedDocument(t *testing.T) {
	srv, clientID := cimdHandler(t, map[string]any{
		"client_name":                "Test Client",
		"token_endpoint_auth_method": "none",
		// redirect_uris deliberately absent
	})
	_, err := srv.getOrFetchClient(t.Context(), clientID)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrClientMetadataValidation)
	assert.ErrorContains(t, err, "redirect_uris is required")
}

// TestTokenEndpointPrivateKeyJWTEndToEnd drives a CIMD private_key_jwt client
// through the real /token handler: form parsing, client metadata fetch,
// negotiation, JWKS retrieval, assertion verification and audience checking.
// The per-piece tests above all bypass one or more of those seams.
func TestTokenEndpointPrivateKeyJWTEndToEnd(t *testing.T) {
	const testHost = "test.example.com"
	const prefix = "/.pomerium/mcp/oauth"

	ctx := context.Background()
	storage := setupTestDatabroker(ctx, t)
	testCipher, err := cryptutil.NewAEADCipher(cryptutil.NewKey())
	require.NoError(t, err)

	key := newAssertionTestKey(t, jose.RS256, "key-1")

	// One server hosts both the client metadata document and its JWKS so a
	// single http.Client trusts both.
	var clientID string
	mux := http.NewServeMux()
	mux.HandleFunc("/jwks.json", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(key.jwks())
	})
	cimd := httptest.NewTLSServer(mux)
	t.Cleanup(cimd.Close)
	mux.HandleFunc("/client.json", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"client_id":                  clientID,
			"client_name":                "Test Client",
			"redirect_uris":              []string{"https://client.example.com/callback"},
			"token_endpoint_auth_method": rfc7591v1.TokenEndpointAuthMethodPrivateKeyJWT,
			"jwks_uri":                   cimd.URL + "/jwks.json",
		})
	})
	clientID = cimd.URL + "/client.json"

	srv := &Handler{
		prefix:                prefix,
		cipher:                testCipher,
		storage:               storage,
		hosts:                 newAutoDiscoveryHosts(testHost, "route-id", "https://upstream.example.com"),
		clientMetadataFetcher: NewClientMetadataFetcher(cimd.Client(), allowAllDomainMatcher()),
		jwksFetcher:           NewJWKSFetcher(cimd.Client(), allowAllDomainMatcher()),
	}

	testSession := session.Create("test-idp", "test-session-id", "test-user-id", time.Now(), 24*time.Hour)
	testSession.OauthToken = &session.OAuthToken{RefreshToken: "upstream-refresh-token"}
	_, err = storage.PutSession(ctx, testSession)
	require.NoError(t, err)

	codeVerifier := "test-code-verifier-that-is-long-enough-for-pkce"

	// Authorization codes are single use, so each request needs its own grant.
	newAuthCode := func(t *testing.T) string {
		t.Helper()
		authReqID, err := storage.CreateAuthorizationRequest(ctx, &oauth21proto.AuthorizationRequest{
			ClientId:            clientID,
			SessionId:           testSession.Id,
			CodeChallenge:       new(computeS256Challenge(codeVerifier)),
			CodeChallengeMethod: new("S256"),
			Scopes:              []string{"openid"},
		})
		require.NoError(t, err)
		authCode, err := CreateCode(CodeTypeAuthorization, authReqID, time.Now().Add(time.Hour), clientID, testCipher)
		require.NoError(t, err)
		return authCode
	}

	post := func(t *testing.T, assertion string) *httptest.ResponseRecorder {
		t.Helper()
		authCode := newAuthCode(t)
		form := url.Values{
			"grant_type":            {"authorization_code"},
			"code":                  {authCode},
			"client_id":             {clientID},
			"code_verifier":         {codeVerifier},
			"client_assertion_type": {oauth21.ClientAssertionTypeJWTBearer},
			"client_assertion":      {assertion},
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, prefix+"/token", strings.NewReader(form.Encode()))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Host = testHost
		w := httptest.NewRecorder()
		srv.Token(w, req)
		return w
	}

	sign := func(aud string) string {
		now := time.Now()
		return key.sign(t, jwt.Claims{
			Issuer: clientID, Subject: clientID, Audience: []string{aud}, ID: uuid.NewString(),
			IssuedAt: jwt.NewNumericDate(now), Expiry: jwt.NewNumericDate(now.Add(2 * time.Minute)),
		})
	}

	t.Run("token endpoint audience", func(t *testing.T) {
		w := post(t, sign("https://"+testHost+prefix+"/token"))
		require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
		var resp map[string]any
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.NotEmpty(t, resp["access_token"])
	})

	t.Run("issuer audience", func(t *testing.T) {
		w := post(t, sign("https://"+testHost))
		assert.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
	})

	t.Run("audience for another authorization server is rejected", func(t *testing.T) {
		w := post(t, sign("https://other-as.example/token"))
		require.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), "invalid_client")
	})

	t.Run("assertion signed by an unknown key is rejected", func(t *testing.T) {
		other := newAssertionTestKey(t, jose.RS256, "key-1")
		now := time.Now()
		w := post(t, other.sign(t, jwt.Claims{
			Issuer: clientID, Subject: clientID, Audience: []string{"https://" + testHost},
			IssuedAt: jwt.NewNumericDate(now), Expiry: jwt.NewNumericDate(now.Add(2 * time.Minute)),
		}))
		require.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), "invalid_client")
	})

	// The /.pomerium/ prefix is reachable via Envoy's catch-all vhost, so an
	// unconfigured Host must not be usable to name an audience.
	t.Run("unconfigured host is rejected", func(t *testing.T) {
		const evil = "other-as.example"
		form := url.Values{
			"grant_type": {"authorization_code"}, "code": {newAuthCode(t)},
			"client_id": {clientID}, "code_verifier": {codeVerifier},
			"client_assertion_type": {oauth21.ClientAssertionTypeJWTBearer},
			"client_assertion":      {sign("https://" + evil)},
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, prefix+"/token", strings.NewReader(form.Encode()))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Host = evil
		w := httptest.NewRecorder()
		srv.Token(w, req)
		require.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), "invalid_client")
	})

	t.Run("missing assertion is rejected", func(t *testing.T) {
		form := url.Values{
			"grant_type": {"authorization_code"}, "code": {newAuthCode(t)},
			"client_id": {clientID}, "code_verifier": {codeVerifier},
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, prefix+"/token", strings.NewReader(form.Encode()))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Host = testHost
		w := httptest.NewRecorder()
		srv.Token(w, req)
		require.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), "invalid_client")
	})
}
