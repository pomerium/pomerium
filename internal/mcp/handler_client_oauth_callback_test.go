package mcp

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	oauth21proto "github.com/pomerium/pomerium/internal/oauth21/gen"
	rfc7591v1 "github.com/pomerium/pomerium/internal/rfc7591"
	"github.com/pomerium/pomerium/pkg/cryptutil"
)

// newTestPendingAuth returns a PendingUpstreamAuth with sensible defaults.
// The tokenEndpointURL is injected from the test's httptest.Server.
func newTestPendingAuth(tokenEndpointURL string) *oauth21proto.PendingUpstreamAuth {
	return &oauth21proto.PendingUpstreamAuth{
		StateId:                   "test-state-id",
		UserId:                    "test-user-id",
		RouteId:                   "test-route-id",
		UpstreamServer:            "https://upstream.example.com",
		PkceVerifier:              "test-pkce-verifier-long-enough-for-oauth",
		Scopes:                    []string{"read", "write"},
		TokenEndpoint:             tokenEndpointURL,
		AuthorizationServerIssuer: "https://auth.example.com",
		OriginalUrl:               "https://upstream.example.com/api/resource",
		RedirectUri:               "https://pomerium.example.com/.pomerium/mcp/client/oauth/callback",
		ClientId:                  "test-client-id",
		DownstreamHost:            "pomerium.example.com",
		CreatedAt:                 timestamppb.Now(),
		ExpiresAt:                 timestamppb.New(time.Now().Add(5 * time.Minute)),
		ResourceParam:             "https://upstream.example.com",
	}
}

// newTokenServer creates an httptest.Server that responds to token exchange requests.
// It captures the last request form values for assertion.
// The responseFunc allows customizing the response per test.
func newTokenServer(t *testing.T, responseFunc func(w http.ResponseWriter, formValues url.Values)) (*httptest.Server, *url.Values) {
	t.Helper()
	var capturedForm url.Values
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		capturedForm, err = url.ParseQuery(string(body))
		require.NoError(t, err)
		responseFunc(w, capturedForm)
	}))
	t.Cleanup(server.Close)
	return server, &capturedForm
}

func successfulTokenResponse(w http.ResponseWriter, _ url.Values) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token":  "upstream-access-token",
		"token_type":    "Bearer",
		"expires_in":    3600,
		"refresh_token": "upstream-refresh-token",
		"scope":         "read write",
	})
}

func TestClientOAuthCallback(t *testing.T) {
	ctx := context.Background()

	t.Run("missing code returns 400", func(t *testing.T) {
		srv := &Handler{}
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/callback?state=some-state", nil)
		srv.ClientOAuthCallback(w, r)
		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), "missing code or state")
	})

	t.Run("missing state returns 400", func(t *testing.T) {
		srv := &Handler{}
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/callback?code=some-code", nil)
		srv.ClientOAuthCallback(w, r)
		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), "missing code or state")
	})

	t.Run("upstream AS error param returns 400", func(t *testing.T) {
		srv := &Handler{}
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/callback?error=access_denied&error_description=user+denied", nil)
		srv.ClientOAuthCallback(w, r)
		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), "Authorization failed")
	})

	t.Run("unknown state ID returns 400", func(t *testing.T) {
		storage := setupTestDatabroker(ctx, t)
		srv := &Handler{storage: storage}

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/callback?code=auth-code&state=nonexistent-state", nil)
		srv.ClientOAuthCallback(w, r)
		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), "Invalid or expired state")
	})

	t.Run("expired pending state returns 400 and cleans up", func(t *testing.T) {
		storage := setupTestDatabroker(ctx, t)
		srv := &Handler{storage: storage}

		pending := newTestPendingAuth("https://unused.example.com/token")
		pending.ExpiresAt = timestamppb.New(time.Now().Add(-1 * time.Minute)) // expired
		require.NoError(t, storage.PutPendingUpstreamAuth(ctx, pending))

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/callback?code=auth-code&state=test-state-id", nil)
		srv.ClientOAuthCallback(w, r)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), "expired")

		// Verify cleanup
		_, err := storage.GetPendingUpstreamAuth(ctx, pending.UserId, pending.DownstreamHost)
		assert.Error(t, err, "pending state should be cleaned up")
	})

	t.Run("token exchange failure invalid_grant returns 502 and cleans up", func(t *testing.T) {
		storage := setupTestDatabroker(ctx, t)

		tokenServer, _ := newTokenServer(t, func(w http.ResponseWriter, _ url.Values) {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
		})

		pending := newTestPendingAuth(tokenServer.URL)
		require.NoError(t, storage.PutPendingUpstreamAuth(ctx, pending))

		srv := &Handler{
			storage:    storage,
			httpClient: tokenServer.Client(),
		}

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/callback?code=auth-code&state=test-state-id", nil)
		srv.ClientOAuthCallback(w, r)

		assert.Equal(t, http.StatusBadGateway, w.Code)

		// Verify cleanup
		_, err := storage.GetPendingUpstreamAuth(ctx, pending.UserId, pending.DownstreamHost)
		assert.Error(t, err, "pending state should be cleaned up after failed exchange")
	})

	t.Run("token exchange failure server error returns 502 and cleans up", func(t *testing.T) {
		storage := setupTestDatabroker(ctx, t)

		tokenServer, _ := newTokenServer(t, func(w http.ResponseWriter, _ url.Values) {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`internal server error`))
		})

		pending := newTestPendingAuth(tokenServer.URL)
		require.NoError(t, storage.PutPendingUpstreamAuth(ctx, pending))

		srv := &Handler{
			storage:    storage,
			httpClient: tokenServer.Client(),
		}

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/callback?code=auth-code&state=test-state-id", nil)
		srv.ClientOAuthCallback(w, r)

		assert.Equal(t, http.StatusBadGateway, w.Code)

		_, err := storage.GetPendingUpstreamAuth(ctx, pending.UserId, pending.DownstreamHost)
		assert.Error(t, err, "pending state should be cleaned up after server error")
	})

	t.Run("happy path verifies token request params", func(t *testing.T) {
		storage := setupTestDatabroker(ctx, t)

		tokenServer, capturedForm := newTokenServer(t, successfulTokenResponse)

		pending := newTestPendingAuth(tokenServer.URL)
		require.NoError(t, storage.PutPendingUpstreamAuth(ctx, pending))

		srv := &Handler{
			storage:    storage,
			httpClient: tokenServer.Client(),
		}

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/callback?code=the-auth-code&state=test-state-id", nil)
		srv.ClientOAuthCallback(w, r)

		require.Equal(t, http.StatusFound, w.Code)

		// Verify all OAuth 2.1 required params sent to upstream AS
		form := *capturedForm
		assert.Equal(t, "authorization_code", form.Get("grant_type"))
		assert.Equal(t, "the-auth-code", form.Get("code"))
		assert.Equal(t, pending.RedirectUri, form.Get("redirect_uri"))
		assert.Equal(t, pending.ClientId, form.Get("client_id"))
		assert.Equal(t, pending.PkceVerifier, form.Get("code_verifier"))
		assert.Equal(t, pending.ResourceParam, form.Get("resource"))
	})

	t.Run("client_secret included when set", func(t *testing.T) {
		storage := setupTestDatabroker(ctx, t)

		tokenServer, capturedForm := newTokenServer(t, successfulTokenResponse)

		pending := newTestPendingAuth(tokenServer.URL)
		pending.ClientSecret = "my-secret"
		require.NoError(t, storage.PutPendingUpstreamAuth(ctx, pending))

		srv := &Handler{
			storage:    storage,
			httpClient: tokenServer.Client(),
		}

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/callback?code=auth-code&state=test-state-id", nil)
		srv.ClientOAuthCallback(w, r)

		require.Equal(t, http.StatusFound, w.Code)
		assert.Equal(t, "my-secret", (*capturedForm).Get("client_secret"))
	})

	t.Run("client_secret omitted when empty", func(t *testing.T) {
		storage := setupTestDatabroker(ctx, t)

		tokenServer, capturedForm := newTokenServer(t, successfulTokenResponse)

		pending := newTestPendingAuth(tokenServer.URL)
		pending.ClientSecret = ""
		require.NoError(t, storage.PutPendingUpstreamAuth(ctx, pending))

		srv := &Handler{
			storage:    storage,
			httpClient: tokenServer.Client(),
		}

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/callback?code=auth-code&state=test-state-id", nil)
		srv.ClientOAuthCallback(w, r)

		require.Equal(t, http.StatusFound, w.Code)
		assert.False(t, (*capturedForm).Has("client_secret"))
	})

	t.Run("resource param falls back to upstream_server", func(t *testing.T) {
		storage := setupTestDatabroker(ctx, t)

		tokenServer, capturedForm := newTokenServer(t, successfulTokenResponse)

		pending := newTestPendingAuth(tokenServer.URL)
		pending.ResourceParam = "" // empty, should fall back
		pending.UpstreamServer = "https://fallback.example.com"
		require.NoError(t, storage.PutPendingUpstreamAuth(ctx, pending))

		srv := &Handler{
			storage:    storage,
			httpClient: tokenServer.Client(),
		}

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/callback?code=auth-code&state=test-state-id", nil)
		srv.ClientOAuthCallback(w, r)

		require.Equal(t, http.StatusFound, w.Code)
		assert.Equal(t, "https://fallback.example.com", (*capturedForm).Get("resource"))
	})

	t.Run("reactive flow stores token and redirects to original URL", func(t *testing.T) {
		storage := setupTestDatabroker(ctx, t)

		tokenServer, _ := newTokenServer(t, successfulTokenResponse)

		pending := newTestPendingAuth(tokenServer.URL)
		pending.AuthReqId = "" // reactive flow — no linked auth request
		require.NoError(t, storage.PutPendingUpstreamAuth(ctx, pending))

		srv := &Handler{
			storage:    storage,
			httpClient: tokenServer.Client(),
		}

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/callback?code=auth-code&state=test-state-id", nil)
		srv.ClientOAuthCallback(w, r)

		assert.Equal(t, http.StatusFound, w.Code)
		assert.Equal(t, pending.OriginalUrl, w.Header().Get("Location"))

		// Verify stored token
		token, err := storage.GetUpstreamMCPToken(ctx, pending.UserId, pending.RouteId, pending.UpstreamServer)
		require.NoError(t, err)
		assert.Equal(t, pending.UserId, token.UserId)
		assert.Equal(t, pending.RouteId, token.RouteId)
		assert.Equal(t, "upstream-access-token", token.AccessToken)
		assert.Equal(t, "upstream-refresh-token", token.RefreshToken)
		assert.Equal(t, "Bearer", token.TokenType)
		assert.NotNil(t, token.ExpiresAt)
		assert.Equal(t, pending.ResourceParam, token.ResourceParam)
		assert.Equal(t, pending.TokenEndpoint, token.TokenEndpoint)
		assert.Equal(t, pending.Scopes, token.Scopes)
		assert.Equal(t, pending.ClientId, token.Audience)
		assert.Equal(t, pending.AuthorizationServerIssuer, token.AuthorizationServerIssuer)

		// Verify pending state deleted
		_, err = storage.GetPendingUpstreamAuth(ctx, pending.UserId, pending.DownstreamHost)
		assert.Error(t, err, "pending state should be deleted after successful callback")
	})

	t.Run("proactive flow stores token and completes MCP auth", func(t *testing.T) {
		storage := setupTestDatabroker(ctx, t)

		key := cryptutil.NewKey()
		testCipher, err := cryptutil.NewAEADCipher(key)
		require.NoError(t, err)

		tokenServer, _ := newTokenServer(t, successfulTokenResponse)

		// Register a downstream client
		clientID, err := storage.RegisterClient(ctx, &rfc7591v1.ClientRegistration{
			ResponseMetadata: &rfc7591v1.Metadata{
				TokenEndpointAuthMethod: proto.String("none"),
				RedirectUris:            []string{"https://mcp-client.example.com/callback"},
			},
		})
		require.NoError(t, err)

		// Create an authorization request (the downstream MCP client auth flow)
		codeVerifier := "test-code-verifier-that-is-long-enough-for-pkce"
		codeChallenge := computeS256Challenge(codeVerifier)
		authReqID, err := storage.CreateAuthorizationRequest(ctx, &oauth21proto.AuthorizationRequest{
			ClientId:            clientID,
			ResponseType:        "code",
			RedirectUri:         proto.String("https://mcp-client.example.com/callback"),
			State:               proto.String("downstream-state"),
			SessionId:           "test-session-id",
			UserId:              "test-user-id",
			CodeChallenge:       proto.String(codeChallenge),
			CodeChallengeMethod: proto.String("S256"),
			Scopes:              []string{"openid"},
		})
		require.NoError(t, err)

		pending := newTestPendingAuth(tokenServer.URL)
		pending.AuthReqId = authReqID // proactive flow — linked auth request
		require.NoError(t, storage.PutPendingUpstreamAuth(ctx, pending))

		srv := &Handler{
			storage:    storage,
			httpClient: tokenServer.Client(),
			cipher:     testCipher,
		}

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/callback?code=auth-code&state=test-state-id", nil)
		srv.ClientOAuthCallback(w, r)

		// AuthorizationResponse should issue a redirect with a Pomerium auth code
		assert.Equal(t, http.StatusFound, w.Code)
		location := w.Header().Get("Location")
		redirectURL, err := url.Parse(location)
		require.NoError(t, err)
		assert.Equal(t, "mcp-client.example.com", redirectURL.Host)
		assert.NotEmpty(t, redirectURL.Query().Get("code"), "should have a Pomerium auth code")
		assert.Equal(t, "downstream-state", redirectURL.Query().Get("state"))

		// Verify upstream token was stored
		token, err := storage.GetUpstreamMCPToken(ctx, pending.UserId, pending.RouteId, pending.UpstreamServer)
		require.NoError(t, err)
		assert.Equal(t, "upstream-access-token", token.AccessToken)

		// Verify pending state deleted
		_, err = storage.GetPendingUpstreamAuth(ctx, pending.UserId, pending.DownstreamHost)
		assert.Error(t, err)
	})

	t.Run("state reuse after successful callback returns 400", func(t *testing.T) {
		storage := setupTestDatabroker(ctx, t)

		tokenServer, _ := newTokenServer(t, successfulTokenResponse)

		pending := newTestPendingAuth(tokenServer.URL)
		pending.AuthReqId = "" // reactive flow
		require.NoError(t, storage.PutPendingUpstreamAuth(ctx, pending))

		srv := &Handler{
			storage:    storage,
			httpClient: tokenServer.Client(),
		}

		// First call succeeds
		w1 := httptest.NewRecorder()
		r1 := httptest.NewRequest(http.MethodGet, "/callback?code=auth-code&state=test-state-id", nil)
		srv.ClientOAuthCallback(w1, r1)
		require.Equal(t, http.StatusFound, w1.Code)

		// Second call with same state fails — state was consumed
		w2 := httptest.NewRecorder()
		r2 := httptest.NewRequest(http.MethodGet, "/callback?code=auth-code&state=test-state-id", nil)
		srv.ClientOAuthCallback(w2, r2)
		assert.Equal(t, http.StatusBadRequest, w2.Code)
	})
}
