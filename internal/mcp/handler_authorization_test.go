package mcp

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/go-jose/go-jose/v3"
	josejwt "github.com/go-jose/go-jose/v3/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/pomerium/pomerium/internal/httputil"
	oauth21proto "github.com/pomerium/pomerium/internal/oauth21/gen"
	rfc7591v1 "github.com/pomerium/pomerium/internal/rfc7591"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	"github.com/pomerium/pomerium/pkg/grpc/session"
)

// authorizeTestStorage implements HandlerStorage for Authorize handler tests.
// Methods with func fields delegate to them; all others panic to catch unexpected calls.
type authorizeTestStorage struct {
	createAuthorizationRequestFunc func(ctx context.Context, req *oauth21proto.AuthorizationRequest) (string, error)
	deleteAuthorizationRequestFunc func(ctx context.Context, id string) error
	getClientFunc                  func(ctx context.Context, id string) (*rfc7591v1.ClientRegistration, error)
	getUpstreamMCPTokenFunc        func(ctx context.Context, userID, routeID, upstreamServer string) (*oauth21proto.UpstreamMCPToken, error)
	getPendingUpstreamAuthFunc     func(ctx context.Context, userID, host string) (*oauth21proto.PendingUpstreamAuth, error)
}

func (s *authorizeTestStorage) CreateAuthorizationRequest(ctx context.Context, req *oauth21proto.AuthorizationRequest) (string, error) {
	if s.createAuthorizationRequestFunc != nil {
		return s.createAuthorizationRequestFunc(ctx, req)
	}
	panic("unexpected call to CreateAuthorizationRequest")
}

func (s *authorizeTestStorage) DeleteAuthorizationRequest(ctx context.Context, id string) error {
	if s.deleteAuthorizationRequestFunc != nil {
		return s.deleteAuthorizationRequestFunc(ctx, id)
	}
	panic("unexpected call to DeleteAuthorizationRequest")
}

func (s *authorizeTestStorage) GetClient(ctx context.Context, id string) (*rfc7591v1.ClientRegistration, error) {
	if s.getClientFunc != nil {
		return s.getClientFunc(ctx, id)
	}
	panic("unexpected call to GetClient")
}

func (s *authorizeTestStorage) GetUpstreamMCPToken(ctx context.Context, userID, routeID, upstreamServer string) (*oauth21proto.UpstreamMCPToken, error) {
	if s.getUpstreamMCPTokenFunc != nil {
		return s.getUpstreamMCPTokenFunc(ctx, userID, routeID, upstreamServer)
	}
	panic("unexpected call to GetUpstreamMCPToken")
}

// Unused HandlerStorage interface methods — panic if called unexpectedly.
func (s *authorizeTestStorage) RegisterClient(context.Context, *rfc7591v1.ClientRegistration) (string, error) {
	panic("unexpected call to RegisterClient")
}

func (s *authorizeTestStorage) GetAuthorizationRequest(context.Context, string) (*oauth21proto.AuthorizationRequest, error) {
	panic("unexpected call to GetAuthorizationRequest")
}

func (s *authorizeTestStorage) GetSession(context.Context, string) (*session.Session, error) {
	panic("unexpected call to GetSession")
}

func (s *authorizeTestStorage) PutSession(context.Context, *session.Session) error {
	panic("unexpected call to PutSession")
}

func (s *authorizeTestStorage) PutMCPRefreshToken(context.Context, *oauth21proto.MCPRefreshToken) error {
	panic("unexpected call to PutMCPRefreshToken")
}

func (s *authorizeTestStorage) GetMCPRefreshToken(context.Context, string) (*oauth21proto.MCPRefreshToken, error) {
	panic("unexpected call to GetMCPRefreshToken")
}

func (s *authorizeTestStorage) DeleteMCPRefreshToken(context.Context, string) error {
	panic("unexpected call to DeleteMCPRefreshToken")
}

func (s *authorizeTestStorage) PutUpstreamMCPToken(context.Context, *oauth21proto.UpstreamMCPToken) error {
	panic("unexpected call to PutUpstreamMCPToken")
}

func (s *authorizeTestStorage) DeleteUpstreamMCPToken(context.Context, string, string, string) error {
	panic("unexpected call to DeleteUpstreamMCPToken")
}

func (s *authorizeTestStorage) PutPendingUpstreamAuth(context.Context, *oauth21proto.PendingUpstreamAuth) error {
	panic("unexpected call to PutPendingUpstreamAuth")
}

func (s *authorizeTestStorage) GetPendingUpstreamAuth(ctx context.Context, userID, host string) (*oauth21proto.PendingUpstreamAuth, error) {
	if s.getPendingUpstreamAuthFunc != nil {
		return s.getPendingUpstreamAuthFunc(ctx, userID, host)
	}
	panic("unexpected call to GetPendingUpstreamAuth")
}

func (s *authorizeTestStorage) DeletePendingUpstreamAuth(context.Context, string, string) error {
	panic("unexpected call to DeletePendingUpstreamAuth")
}

func (s *authorizeTestStorage) GetPendingUpstreamAuthByState(context.Context, string) (*oauth21proto.PendingUpstreamAuth, error) {
	panic("unexpected call to GetPendingUpstreamAuthByState")
}

func (s *authorizeTestStorage) GetUpstreamOAuthClient(context.Context, string, string) (*oauth21proto.UpstreamOAuthClient, error) {
	panic("unexpected call to GetUpstreamOAuthClient")
}

func (s *authorizeTestStorage) PutUpstreamOAuthClient(context.Context, *oauth21proto.UpstreamOAuthClient) error {
	panic("unexpected call to PutUpstreamOAuthClient")
}

// makeTestJWT creates a minimal JWT with sid and sub claims for testing.
func makeTestJWT(t *testing.T, sessionID, userID string) string {
	t.Helper()
	key := []byte("test-secret-key-32-bytes-long!!")
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: key}, nil)
	require.NoError(t, err)
	claims := map[string]any{"sid": sessionID, "sub": userID}
	raw, err := josejwt.Signed(signer).Claims(claims).CompactSerialize()
	require.NoError(t, err)
	return raw
}

// makeAuthorizeURL builds a URL for the authorize endpoint with the required query parameters.
func makeAuthorizeURL(t *testing.T, clientID, redirectURI string) string {
	t.Helper()
	codeVerifier := "test-code-verifier-that-is-long-enough-for-pkce-requirements"
	sha256Hash := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(sha256Hash[:])

	params := url.Values{
		"client_id":             {clientID},
		"redirect_uri":          {redirectURI},
		"response_type":         {"code"},
		"code_challenge":        {codeChallenge},
		"code_challenge_method": {"S256"},
		"state":                 {"test-state"},
	}
	return fmt.Sprintf("https://test.example.com/.pomerium/mcp/authorize?%s", params.Encode())
}

// newAuthorizeTestHandler creates a Handler configured for authorize endpoint tests
// with the given storage and hosts. It uses a test cipher and dummy client metadata fetcher.
func newAuthorizeTestHandler(t *testing.T, store HandlerStorage, hosts *HostInfo) *Handler {
	t.Helper()
	key := cryptutil.NewKey()
	testCipher, err := cryptutil.NewAEADCipher(key)
	require.NoError(t, err)

	return &Handler{
		prefix:  DefaultPrefix,
		storage: store,
		cipher:  testCipher,
		hosts:   hosts,
	}
}

// newAutoDiscoveryHosts creates a HostInfo with a single auto-discovery server.
// The server has the given host, routeID, and upstreamURL, and no OAuth2 Config (auto-discovery).
func newAutoDiscoveryHosts(host, routeID, upstreamURL string) *HostInfo {
	return newHostInfoForTest(
		map[string]ServerHostInfo{
			host: {
				Host:        host,
				RouteID:     routeID,
				UpstreamURL: upstreamURL,
				// UpstreamOAuth2 is nil → UsesAutoDiscovery returns true
			},
		},
		nil,
	)
}

func TestAuthorize_GetUpstreamMCPToken_StorageError(t *testing.T) {
	t.Parallel()

	const (
		testHost        = "test.example.com"
		testRouteID     = "test-route-id"
		testUpstreamURL = "https://upstream.example.com"
		testClientID    = "test-client-id"
		testRedirectURI = "https://client.example.com/callback"
		testSessionID   = "test-session"
		testUserID      = "test-user"
	)

	var deleteAuthReqCalled bool
	var deletedAuthReqID string

	store := &authorizeTestStorage{
		createAuthorizationRequestFunc: func(_ context.Context, _ *oauth21proto.AuthorizationRequest) (string, error) {
			return "test-auth-req-id", nil
		},
		getUpstreamMCPTokenFunc: func(_ context.Context, _, _, _ string) (*oauth21proto.UpstreamMCPToken, error) {
			return nil, status.Error(codes.Internal, "storage down")
		},
		deleteAuthorizationRequestFunc: func(_ context.Context, id string) error {
			deleteAuthReqCalled = true
			deletedAuthReqID = id
			return nil
		},
		getClientFunc: func(_ context.Context, _ string) (*rfc7591v1.ClientRegistration, error) {
			return &rfc7591v1.ClientRegistration{
				ResponseMetadata: &rfc7591v1.Metadata{
					TokenEndpointAuthMethod: new("none"),
					RedirectUris:            []string{testRedirectURI},
				},
			}, nil
		},
	}

	hosts := newAutoDiscoveryHosts(testHost, testRouteID, testUpstreamURL)
	srv := newAuthorizeTestHandler(t, store, hosts)

	reqURL := makeAuthorizeURL(t, testClientID, testRedirectURI)
	r := httptest.NewRequest(http.MethodGet, reqURL, nil)
	r.Host = testHost
	r.Header.Set(httputil.HeaderPomeriumJWTAssertion, makeTestJWT(t, testSessionID, testUserID))

	w := httptest.NewRecorder()
	srv.Authorize(w, r)

	assert.Equal(t, http.StatusInternalServerError, w.Code, "should return 500 on storage error")
	assert.Contains(t, w.Body.String(), "internal error")
	assert.True(t, deleteAuthReqCalled, "should clean up auth request on storage error")
	assert.Equal(t, "test-auth-req-id", deletedAuthReqID, "should delete the correct auth request")
}

func TestAuthorize_MissingUpstreamURL_IssuesAuthCode(t *testing.T) {
	t.Parallel()

	const (
		testHost        = "test.example.com"
		testClientID    = "test-client-id"
		testRedirectURI = "https://client.example.com/callback"
		testSessionID   = "test-session"
		testUserID      = "test-user"
	)

	store := &authorizeTestStorage{
		createAuthorizationRequestFunc: func(_ context.Context, _ *oauth21proto.AuthorizationRequest) (string, error) {
			return "test-auth-req-id", nil
		},
		getClientFunc: func(_ context.Context, _ string) (*rfc7591v1.ClientRegistration, error) {
			return &rfc7591v1.ClientRegistration{
				ResponseMetadata: &rfc7591v1.Metadata{
					TokenEndpointAuthMethod: new("none"),
					RedirectUris:            []string{testRedirectURI},
				},
			}, nil
		},
	}

	// When UpstreamURL is empty, no upstream OAuth is needed — the handler should
	// fall through to issue an auth code directly.
	hosts := newAutoDiscoveryHosts(testHost, "some-route-id", "" /* empty UpstreamURL */)
	srv := newAuthorizeTestHandler(t, store, hosts)

	reqURL := makeAuthorizeURL(t, testClientID, testRedirectURI)
	r := httptest.NewRequest(http.MethodGet, reqURL, nil)
	r.Host = testHost
	r.Header.Set(httputil.HeaderPomeriumJWTAssertion, makeTestJWT(t, testSessionID, testUserID))

	w := httptest.NewRecorder()
	srv.Authorize(w, r)

	assert.Equal(t, http.StatusFound, w.Code, "should redirect with auth code when no upstream URL")
	loc := w.Header().Get("Location")
	assert.Contains(t, loc, "code=", "redirect should contain authorization code")
	assert.Contains(t, loc, "state=test-state", "redirect should preserve state parameter")
}

func TestAuthorize_GetUpstreamMCPToken_NotFoundFallsThrough(t *testing.T) {
	t.Parallel()

	const (
		testHost        = "test.example.com"
		testRouteID     = "test-route-id"
		testClientID    = "test-client-id"
		testRedirectURI = "https://client.example.com/callback"
		testSessionID   = "test-session"
		testUserID      = "test-user"
	)

	// Create a test upstream server that returns 404 for PRM discovery,
	// causing resolveAutoDiscoveryAuth to return a DiscoveryError (non-fatal).
	upstreamSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	}))
	t.Cleanup(upstreamSrv.Close)

	var deleteAuthReqCalled bool

	store := &authorizeTestStorage{
		createAuthorizationRequestFunc: func(_ context.Context, _ *oauth21proto.AuthorizationRequest) (string, error) {
			return "test-auth-req-id", nil
		},
		getUpstreamMCPTokenFunc: func(_ context.Context, _, _, _ string) (*oauth21proto.UpstreamMCPToken, error) {
			// NotFound is expected — user doesn't have a cached token yet.
			return nil, status.Error(codes.NotFound, "not found")
		},
		deleteAuthorizationRequestFunc: func(_ context.Context, _ string) error {
			deleteAuthReqCalled = true
			return nil
		},
		getClientFunc: func(_ context.Context, _ string) (*rfc7591v1.ClientRegistration, error) {
			return &rfc7591v1.ClientRegistration{
				ResponseMetadata: &rfc7591v1.Metadata{
					TokenEndpointAuthMethod: new("none"),
					RedirectUris:            []string{testRedirectURI},
				},
			}, nil
		},
		getPendingUpstreamAuthFunc: func(_ context.Context, _, _ string) (*oauth21proto.PendingUpstreamAuth, error) {
			return nil, fmt.Errorf("no pending auth")
		},
	}

	hosts := newAutoDiscoveryHosts(testHost, testRouteID, upstreamSrv.URL)
	srv := newAuthorizeTestHandler(t, store, hosts)
	srv.httpClient = upstreamSrv.Client()
	srv.asMetadataDomainMatcher = NewDomainMatcher(nil) // allow all

	reqURL := makeAuthorizeURL(t, testClientID, testRedirectURI)
	r := httptest.NewRequest(http.MethodGet, reqURL, nil)
	r.Host = testHost
	r.Header.Set(httputil.HeaderPomeriumJWTAssertion, makeTestJWT(t, testSessionID, testUserID))

	w := httptest.NewRecorder()
	srv.Authorize(w, r)

	// A NotFound error should NOT trigger a 500 or cleanup — the flow should continue
	// to auto-discovery (which fails gracefully with DiscoveryError) and then issue an auth code.
	assert.NotEqual(t, http.StatusInternalServerError, w.Code,
		"NotFound error should not cause a 500")
	assert.False(t, deleteAuthReqCalled,
		"should not clean up auth request on NotFound (flow continues)")
}
