package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/internal/httputil"
	oauth21proto "github.com/pomerium/pomerium/internal/oauth21/gen"
)

// refreshRoutesTestStorage is an in-memory upstream MCP token store for the
// routes/refresh handler tests.
type refreshRoutesTestStorage struct {
	HandlerStorage

	mu     sync.Mutex
	tokens map[string]*oauth21proto.UpstreamMCPToken // key: userID|routeID|upstreamServer
}

func (s *refreshRoutesTestStorage) key(userID, routeID, upstreamServer string) string {
	return userID + "|" + routeID + "|" + upstreamServer
}

func (s *refreshRoutesTestStorage) GetUpstreamMCPToken(_ context.Context, userID, routeID, upstreamServer string) (*oauth21proto.UpstreamMCPToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if tok, ok := s.tokens[s.key(userID, routeID, upstreamServer)]; ok {
		return tok, nil
	}
	return nil, status.Error(codes.NotFound, "not found")
}

func (s *refreshRoutesTestStorage) PutUpstreamMCPToken(_ context.Context, token *oauth21proto.UpstreamMCPToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens[s.key(token.GetUserId(), token.GetRouteId(), token.GetUpstreamServer())] = token
	return nil
}

func (s *refreshRoutesTestStorage) DeleteUpstreamMCPToken(_ context.Context, userID, routeID, upstreamServer string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.tokens, s.key(userID, routeID, upstreamServer))
	return nil
}

func (s *refreshRoutesTestStorage) get(userID, routeID, upstreamServer string) *oauth21proto.UpstreamMCPToken {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tokens[s.key(userID, routeID, upstreamServer)]
}

type refreshRoutesResponse struct {
	Servers []struct {
		URL                   string `json:"url"`
		Connected             bool   `json:"connected"`
		TokenExpiresAt        string `json:"token_expires_at"`
		RefreshTokenAvailable bool   `json:"refresh_token_available"`
		RefreshTokenExpiresAt string `json:"refresh_token_expires_at"`
	} `json:"servers"`
	Errors map[string]string `json:"errors"`
}

const (
	refreshTestRouteURL = "https://mcp.example.com"
	refreshTestHostname = "mcp.example.com"
	refreshTestRouteID  = "route-1"
	refreshTestUpstream = "https://upstream.example.com/mcp"

	refreshTestUserID    = "refresh-test-user"
	refreshTestSessionID = "refresh-test-session"
)

// newRefreshTestHandler builds a Handler with a single MCP server route and an
// in-memory token store.
// It returns the handler, the store and the URL of the fake upstream token endpoint
// (empty when no token endpoint handler was supplied).
func newRefreshTestHandler(t *testing.T, tokenEndpointHandler http.HandlerFunc) (*Handler, *refreshRoutesTestStorage, string) {
	t.Helper()

	storage := &refreshRoutesTestStorage{tokens: map[string]*oauth21proto.UpstreamMCPToken{}}
	httpClient := http.DefaultClient
	var tokenEndpoint string
	if tokenEndpointHandler != nil {
		ts := httptest.NewServer(tokenEndpointHandler)
		t.Cleanup(ts.Close)
		httpClient = ts.Client()
		tokenEndpoint = ts.URL
	}

	srv := &Handler{
		prefix:  DefaultPrefix,
		storage: storage,
		hosts: newHostInfoForTest(map[string]ServerHostInfo{
			refreshTestHostname: {
				Name:        "Example",
				Host:        refreshTestHostname,
				URL:         refreshTestRouteURL,
				UpstreamURL: refreshTestUpstream,
				RouteID:     refreshTestRouteID,
			},
		}, nil),
		httpClient: httpClient,
	}
	return srv, storage, tokenEndpoint
}

func refreshRequest(t *testing.T, body string, authenticated bool) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, DefaultPrefix+"/routes/refresh", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	if authenticated {
		r.Header.Set(httputil.HeaderPomeriumJWTAssertion, makeTestJWT(t, refreshTestSessionID, refreshTestUserID))
	}
	return r
}

func decodeRefreshResponse(t *testing.T, w *httptest.ResponseRecorder) refreshRoutesResponse {
	t.Helper()
	var resp refreshRoutesResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	return resp
}

func TestRefreshRoutesSuccess(t *testing.T) {
	t.Parallel()

	srv, storage, tokenEndpoint := newRefreshTestHandler(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"new-at","refresh_token":"new-rt","token_type":"Bearer","expires_in":3600}`))
	})

	require.NoError(t, storage.PutUpstreamMCPToken(context.Background(), &oauth21proto.UpstreamMCPToken{
		UserId:         refreshTestUserID,
		RouteId:        refreshTestRouteID,
		UpstreamServer: refreshTestUpstream,
		AccessToken:    "old-at",
		RefreshToken:   "old-rt",
		TokenEndpoint:  tokenEndpoint,
		ClientId:       "client-1",
		// still valid: refresh must happen anyway
		ExpiresAt: timestamppb.New(time.Now().Add(time.Hour)),
	}))

	w := httptest.NewRecorder()
	srv.RefreshRoutes(w, refreshRequest(t, `{"routes":["`+refreshTestRouteURL+`"]}`, true))

	require.Equal(t, http.StatusOK, w.Code)
	resp := decodeRefreshResponse(t, w)
	assert.Empty(t, resp.Errors)
	require.Len(t, resp.Servers, 1)
	assert.Equal(t, refreshTestRouteURL, resp.Servers[0].URL)
	assert.True(t, resp.Servers[0].Connected)
	assert.True(t, resp.Servers[0].RefreshTokenAvailable)
	require.NotEmpty(t, resp.Servers[0].TokenExpiresAt)
	expiry, err := time.Parse(time.RFC3339, resp.Servers[0].TokenExpiresAt)
	require.NoError(t, err)
	assert.WithinDuration(t, time.Now().Add(time.Hour), expiry, time.Minute)

	stored := storage.get(refreshTestUserID, refreshTestRouteID, refreshTestUpstream)
	require.NotNil(t, stored)
	assert.Equal(t, "new-at", stored.GetAccessToken())
	assert.Equal(t, "new-rt", stored.GetRefreshToken())
}

func TestRefreshRoutesNotConnected(t *testing.T) {
	t.Parallel()

	srv, _, _ := newRefreshTestHandler(t, nil)

	w := httptest.NewRecorder()
	srv.RefreshRoutes(w, refreshRequest(t, `{"routes":["`+refreshTestRouteURL+`"]}`, true))

	require.Equal(t, http.StatusOK, w.Code)
	resp := decodeRefreshResponse(t, w)
	require.Contains(t, resp.Errors, refreshTestRouteURL)
	assert.Contains(t, resp.Errors[refreshTestRouteURL], "not connected")
	require.Len(t, resp.Servers, 1)
	assert.False(t, resp.Servers[0].Connected)
}

func TestRefreshRoutesNoRefreshToken(t *testing.T) {
	t.Parallel()

	srv, storage, _ := newRefreshTestHandler(t, nil)

	require.NoError(t, storage.PutUpstreamMCPToken(context.Background(), &oauth21proto.UpstreamMCPToken{
		UserId:         refreshTestUserID,
		RouteId:        refreshTestRouteID,
		UpstreamServer: refreshTestUpstream,
		AccessToken:    "old-at",
		TokenEndpoint:  "https://upstream.example.com/token",
	}))

	w := httptest.NewRecorder()
	srv.RefreshRoutes(w, refreshRequest(t, `{"routes":["`+refreshTestRouteURL+`"]}`, true))

	require.Equal(t, http.StatusOK, w.Code)
	resp := decodeRefreshResponse(t, w)
	require.Contains(t, resp.Errors, refreshTestRouteURL)
	assert.Contains(t, resp.Errors[refreshTestRouteURL], "cannot be refreshed")
	// the token must be preserved
	assert.NotNil(t, storage.get(refreshTestUserID, refreshTestRouteID, refreshTestUpstream))
	require.Len(t, resp.Servers, 1)
	assert.True(t, resp.Servers[0].Connected)
}

func TestRefreshRoutesPermanentFailure(t *testing.T) {
	t.Parallel()

	srv, storage, tokenEndpoint := newRefreshTestHandler(t, func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
	})

	require.NoError(t, storage.PutUpstreamMCPToken(context.Background(), &oauth21proto.UpstreamMCPToken{
		UserId:         refreshTestUserID,
		RouteId:        refreshTestRouteID,
		UpstreamServer: refreshTestUpstream,
		AccessToken:    "old-at",
		RefreshToken:   "old-rt",
		TokenEndpoint:  tokenEndpoint,
	}))

	w := httptest.NewRecorder()
	srv.RefreshRoutes(w, refreshRequest(t, `{"routes":["`+refreshTestRouteURL+`"]}`, true))

	require.Equal(t, http.StatusOK, w.Code)
	resp := decodeRefreshResponse(t, w)
	require.Contains(t, resp.Errors, refreshTestRouteURL)
	assert.Nil(t, storage.get(refreshTestUserID, refreshTestRouteID, refreshTestUpstream),
		"permanent failure must clear the stored token")
	require.Len(t, resp.Servers, 1)
	assert.False(t, resp.Servers[0].Connected)
}

func TestRefreshRoutesTransientFailure(t *testing.T) {
	t.Parallel()

	srv, storage, tokenEndpoint := newRefreshTestHandler(t, func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	})

	require.NoError(t, storage.PutUpstreamMCPToken(context.Background(), &oauth21proto.UpstreamMCPToken{
		UserId:         refreshTestUserID,
		RouteId:        refreshTestRouteID,
		UpstreamServer: refreshTestUpstream,
		AccessToken:    "old-at",
		RefreshToken:   "old-rt",
		TokenEndpoint:  tokenEndpoint,
	}))

	w := httptest.NewRecorder()
	srv.RefreshRoutes(w, refreshRequest(t, `{"routes":["`+refreshTestRouteURL+`"]}`, true))

	require.Equal(t, http.StatusOK, w.Code)
	resp := decodeRefreshResponse(t, w)
	require.Contains(t, resp.Errors, refreshTestRouteURL)
	assert.NotNil(t, storage.get(refreshTestUserID, refreshTestRouteID, refreshTestUpstream),
		"transient failure must preserve the stored token")
	require.Len(t, resp.Servers, 1)
	assert.True(t, resp.Servers[0].Connected)
}

func TestRefreshRoutesBadRequest(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		body string
	}{
		{name: "malformed json", body: `{`},
		{name: "no routes", body: `{"routes":[]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			srv, _, _ := newRefreshTestHandler(t, nil)
			w := httptest.NewRecorder()
			srv.RefreshRoutes(w, refreshRequest(t, tc.body, true))
			assert.Equal(t, http.StatusBadRequest, w.Code)
		})
	}
}

func TestRefreshRoutesUnauthenticated(t *testing.T) {
	t.Parallel()

	srv, _, _ := newRefreshTestHandler(t, nil)

	w := httptest.NewRecorder()
	srv.RefreshRoutes(w, refreshRequest(t, `{"routes":["`+refreshTestRouteURL+`"]}`, false))

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestRefreshRoutesMuxWiring exercises the endpoint through HandlerFunc so the
// route registration is covered.
func TestRefreshRoutesMuxWiring(t *testing.T) {
	t.Parallel()

	srv, storage, tokenEndpoint := newRefreshTestHandler(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"new-at","token_type":"Bearer","expires_in":60}`))
	})

	require.NoError(t, storage.PutUpstreamMCPToken(context.Background(), &oauth21proto.UpstreamMCPToken{
		UserId:         refreshTestUserID,
		RouteId:        refreshTestRouteID,
		UpstreamServer: refreshTestUpstream,
		AccessToken:    "old-at",
		RefreshToken:   "old-rt",
		TokenEndpoint:  tokenEndpoint,
	}))

	w := httptest.NewRecorder()
	srv.HandlerFunc()(w, refreshRequest(t, `{"routes":["`+refreshTestRouteURL+`"]}`, true))

	require.Equal(t, http.StatusOK, w.Code)
	resp := decodeRefreshResponse(t, w)
	assert.Empty(t, resp.Errors)
	require.Len(t, resp.Servers, 1)
	assert.True(t, resp.Servers[0].Connected)

	stored := storage.get(refreshTestUserID, refreshTestRouteID, refreshTestUpstream)
	require.NotNil(t, stored)
	assert.Equal(t, "new-at", stored.GetAccessToken())
	assert.Equal(t, "old-rt", stored.GetRefreshToken(), "refresh token is preserved when not rotated")
}
