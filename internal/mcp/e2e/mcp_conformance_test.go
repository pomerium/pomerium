package e2e

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/config"
	mcphandler "github.com/pomerium/pomerium/internal/mcp"
	"github.com/pomerium/pomerium/internal/testenv"
	"github.com/pomerium/pomerium/internal/testenv/scenarios"
	"github.com/pomerium/pomerium/internal/testenv/snippets"
	"github.com/pomerium/pomerium/internal/testenv/upstreams"
	"github.com/pomerium/pomerium/pkg/cryptutil"
)

// TestMCPConformance tests OAuth 2.1 conformance for MCP authorization server.
// These tests verify security-critical behavior that maps to the MCP conformance suite:
// https://github.com/modelcontextprotocol/conformance
func TestMCPConformance(t *testing.T) {
	t.Parallel()
	env := testenv.New(t)

	env.Add(testenv.ModifierFunc(func(_ context.Context, cfg *config.Config) {
		if cfg.Options.RuntimeFlags == nil {
			cfg.Options.RuntimeFlags = make(config.RuntimeFlags)
		}
		cfg.Options.RuntimeFlags[config.RuntimeFlagMCP] = true
		cfg.Options.MCPAllowedClientIDDomains = []string{"*"}
	}))

	idp := scenarios.NewIDP([]*scenarios.User{
		{Email: "user@example.com"},
	})
	env.Add(idp)

	mcpServer := mcp.NewServer(&mcp.Implementation{
		Name:    "conformance-test-server",
		Version: "1.0.0",
	}, nil)
	mcp.AddTool(mcpServer, &mcp.Tool{
		Name:        "ping",
		Description: "Returns pong",
	}, func(_ context.Context, _ *mcp.CallToolRequest, _ any) (*mcp.CallToolResult, any, error) {
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: "pong"}},
		}, nil, nil
	})

	serverUpstream := upstreams.HTTP(nil, upstreams.WithDisplayName("MCP Conformance Server"))
	serverHandler := mcp.NewStreamableHTTPHandler(func(_ *http.Request) *mcp.Server {
		return mcpServer
	}, nil)
	serverUpstream.Handle("/", serverHandler.ServeHTTP)

	serverRoute := serverUpstream.Route().
		From(env.SubdomainURL("mcp-conformance")).
		Policy(func(p *config.Policy) {
			p.AllowedDomains = []string{"example.com"}
			p.MCP = &config.MCP{Server: &config.MCPServer{}}
		})
	env.AddUpstream(serverUpstream)

	env.Start()
	snippets.WaitStartupComplete(env)

	ctx := env.Context()
	mcpServerURL := serverRoute.URL().Value()
	parsedURL, err := url.Parse(mcpServerURL)
	require.NoError(t, err)

	baseHTTPClient := func() *http.Client {
		c := upstreams.NewHTTPClient(env.ServerCAs(), &upstreams.RequestOptions{})
		c.Jar, _ = cookiejar.New(nil)
		c.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		}
		return c
	}

	// Fetch AS metadata once for all subtests
	asMetadataURL := "https://" + parsedURL.Host + mcphandler.WellKnownAuthorizationServerEndpoint
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, asMetadataURL, nil)
	require.NoError(t, err)
	resp, err := baseHTTPClient().Do(req)
	require.NoError(t, err)
	var asMetadata mcphandler.AuthorizationServerMetadata
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&asMetadata))
	resp.Body.Close()

	// Helper: register a client with specific auth method
	registerClient := func(t *testing.T, authMethod string) (clientID, clientSecret string) {
		t.Helper()
		clientMetadata := map[string]any{
			"redirect_uris":              []string{"http://localhost:8080/callback"},
			"client_name":                "Conformance Test Client",
			"token_endpoint_auth_method": authMethod,
			"grant_types":                []string{"authorization_code", "refresh_token"},
			"response_types":             []string{"code"},
		}
		body, _ := json.Marshal(clientMetadata)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, asMetadata.RegistrationEndpoint, strings.NewReader(string(body)))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")
		resp, err := baseHTTPClient().Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)
		var regResp map[string]any
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&regResp))
		clientID, _ = regResp["client_id"].(string)
		clientSecret, _ = regResp["client_secret"].(string)
		return clientID, clientSecret
	}

	// Helper: get authorization code via full auth flow
	getAuthCode := func(t *testing.T, clientID, codeVerifier string) string {
		t.Helper()
		codeChallenge := generateS256Challenge(codeVerifier)
		state := cryptutil.NewRandomStringN(32)
		redirectURI := "http://localhost:8080/callback"

		authParams := url.Values{
			"response_type":         {"code"},
			"client_id":             {clientID},
			"redirect_uri":          {redirectURI},
			"state":                 {state},
			"code_challenge":        {codeChallenge},
			"code_challenge_method": {"S256"},
		}

		authURL := asMetadata.AuthorizationEndpoint + "?" + authParams.Encode()
		authClient := upstreams.NewHTTPClient(env.ServerCAs(), &upstreams.RequestOptions{})
		authClient.Jar, _ = cookiejar.New(nil)
		authClient.CheckRedirect = func(req *http.Request, _ []*http.Request) error {
			if strings.HasPrefix(req.URL.String(), redirectURI) {
				return http.ErrUseLastResponse
			}
			return nil
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, authURL, nil)
		require.NoError(t, err)
		resp, err := upstreams.AuthenticateFlow(ctx, authClient, req, "user@example.com", false)
		require.NoError(t, err)
		defer resp.Body.Close()

		code, _ := parseCallbackParams(t, resp.Header.Get("Location"))
		require.NotEmpty(t, code)
		return code
	}

	// Helper: make token request and return response
	doTokenRequest := func(t *testing.T, params url.Values, basicAuth *[2]string) (*http.Response, map[string]any) {
		t.Helper()
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, asMetadata.TokenEndpoint, strings.NewReader(params.Encode()))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if basicAuth != nil {
			credentials := base64.StdEncoding.EncodeToString([]byte(basicAuth[0] + ":" + basicAuth[1]))
			req.Header.Set("Authorization", "Basic "+credentials)
		}
		resp, err := baseHTTPClient().Do(req)
		require.NoError(t, err)
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		var result map[string]any
		_ = json.Unmarshal(body, &result)
		t.Logf("Token response: status=%d body=%s", resp.StatusCode, string(body))
		return resp, result
	}

	// ============================================================================
	// Test #1: Token Endpoint Authentication Methods (client_secret_basic)
	// Conformance: https://github.com/modelcontextprotocol/conformance/blob/main/src/scenarios/client/auth/token-endpoint-auth.ts
	// ============================================================================
	t.Run("token_endpoint_auth_client_secret_basic", func(t *testing.T) {
		clientID, clientSecret := registerClient(t, "client_secret_basic")
		codeVerifier := cryptutil.NewRandomStringN(64)
		authCode := getAuthCode(t, clientID, codeVerifier)

		t.Run("valid_basic_auth_succeeds", func(t *testing.T) {
			params := url.Values{
				"grant_type":    {"authorization_code"},
				"code":          {authCode},
				"redirect_uri":  {"http://localhost:8080/callback"},
				"client_id":     {clientID},
				"code_verifier": {codeVerifier},
			}
			resp, result := doTokenRequest(t, params, &[2]string{clientID, clientSecret})
			assert.Equal(t, http.StatusOK, resp.StatusCode)
			assert.NotEmpty(t, result["access_token"])
			assert.Equal(t, "Bearer", result["token_type"])
		})

		t.Run("missing_basic_auth_fails", func(t *testing.T) {
			t.Skip("TODO: client_secret_basic validation not yet implemented in handler_token.go")

			// Need a new auth code since the previous one was consumed
			newCodeVerifier := cryptutil.NewRandomStringN(64)
			newAuthCode := getAuthCode(t, clientID, newCodeVerifier)

			params := url.Values{
				"grant_type":    {"authorization_code"},
				"code":          {newAuthCode},
				"redirect_uri":  {"http://localhost:8080/callback"},
				"client_id":     {clientID},
				"code_verifier": {newCodeVerifier},
			}
			resp, result := doTokenRequest(t, params, nil) // No auth header
			assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
			assert.Equal(t, "invalid_request", result["error"])
		})

		t.Run("wrong_secret_fails", func(t *testing.T) {
			t.Skip("TODO: client_secret_basic validation not yet implemented in handler_token.go")

			newCodeVerifier := cryptutil.NewRandomStringN(64)
			newAuthCode := getAuthCode(t, clientID, newCodeVerifier)

			params := url.Values{
				"grant_type":    {"authorization_code"},
				"code":          {newAuthCode},
				"redirect_uri":  {"http://localhost:8080/callback"},
				"client_id":     {clientID},
				"code_verifier": {newCodeVerifier},
			}
			resp, result := doTokenRequest(t, params, &[2]string{clientID, "wrong-secret"})
			assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
			assert.Equal(t, "invalid_request", result["error"])
		})
	})

	// ============================================================================
	// Test #2: PKCE Code Verifier Validation
	// MCP Authorization Spec (2025-11-25):
	//   "MCP clients MUST implement PKCE according to OAuth 2.1 Section 7.5.2"
	//   "MCP clients MUST use the S256 code challenge method when technically capable"
	// Conformance: https://github.com/modelcontextprotocol/conformance/blob/main/src/scenarios/client/auth/pkce-validation.ts
	// ============================================================================
	t.Run("pkce_code_verifier_validation", func(t *testing.T) {
		clientID, _ := registerClient(t, "none")

		t.Run("wrong_verifier_fails", func(t *testing.T) {
			codeVerifier := cryptutil.NewRandomStringN(64)
			authCode := getAuthCode(t, clientID, codeVerifier)

			params := url.Values{
				"grant_type":    {"authorization_code"},
				"code":          {authCode},
				"redirect_uri":  {"http://localhost:8080/callback"},
				"client_id":     {clientID},
				"code_verifier": {"completely-different-verifier-that-does-not-match"},
			}
			resp, result := doTokenRequest(t, params, nil)
			assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
			assert.Equal(t, "invalid_grant", result["error"])
		})

		t.Run("missing_verifier_fails", func(t *testing.T) {
			codeVerifier := cryptutil.NewRandomStringN(64)
			authCode := getAuthCode(t, clientID, codeVerifier)

			params := url.Values{
				"grant_type":   {"authorization_code"},
				"code":         {authCode},
				"redirect_uri": {"http://localhost:8080/callback"},
				"client_id":    {clientID},
				// code_verifier intentionally omitted
			}
			resp, result := doTokenRequest(t, params, nil)
			assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
			assert.Equal(t, "invalid_grant", result["error"])
		})

		t.Run("empty_verifier_fails", func(t *testing.T) {
			codeVerifier := cryptutil.NewRandomStringN(64)
			authCode := getAuthCode(t, clientID, codeVerifier)

			params := url.Values{
				"grant_type":    {"authorization_code"},
				"code":          {authCode},
				"redirect_uri":  {"http://localhost:8080/callback"},
				"client_id":     {clientID},
				"code_verifier": {""},
			}
			resp, result := doTokenRequest(t, params, nil)
			assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
			assert.Equal(t, "invalid_grant", result["error"])
		})
	})

	// ============================================================================
	// Test #3: Authorization Code Replay Protection
	// MCP Authorization Spec (2025-11-25), referencing OAuth 2.1 Section 4.1.3:
	//   Authorization codes MUST be one-time use. If an authorization code is
	//   used more than once, the authorization server MUST deny the request.
	// ============================================================================
	t.Run("authorization_code_replay_protection", func(t *testing.T) {
		clientID, _ := registerClient(t, "none")

		t.Run("code_reuse_fails", func(t *testing.T) {
			codeVerifier := cryptutil.NewRandomStringN(64)
			authCode := getAuthCode(t, clientID, codeVerifier)

			params := url.Values{
				"grant_type":    {"authorization_code"},
				"code":          {authCode},
				"redirect_uri":  {"http://localhost:8080/callback"},
				"client_id":     {clientID},
				"code_verifier": {codeVerifier},
			}

			// First use should succeed
			resp1, result1 := doTokenRequest(t, params, nil)
			assert.Equal(t, http.StatusOK, resp1.StatusCode)
			assert.NotEmpty(t, result1["access_token"])

			// Second use of same code should fail
			resp2, result2 := doTokenRequest(t, params, nil)
			assert.Equal(t, http.StatusBadRequest, resp2.StatusCode)
			assert.Equal(t, "invalid_grant", result2["error"])
		})

		t.Run("code_for_different_client_fails", func(t *testing.T) {
			// Register two clients
			client1ID, _ := registerClient(t, "none")
			client2ID, _ := registerClient(t, "none")

			// Get code for client1
			codeVerifier := cryptutil.NewRandomStringN(64)
			authCode := getAuthCode(t, client1ID, codeVerifier)

			// Try to use it with client2
			params := url.Values{
				"grant_type":    {"authorization_code"},
				"code":          {authCode},
				"redirect_uri":  {"http://localhost:8080/callback"},
				"client_id":     {client2ID}, // Different client!
				"code_verifier": {codeVerifier},
			}
			resp, result := doTokenRequest(t, params, nil)
			assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
			assert.Equal(t, "invalid_grant", result["error"])
		})
	})

	// ============================================================================
	// Test #4: Refresh Token Security
	// MCP Authorization Spec (2025-11-25):
	//   "Clients and servers MUST implement secure token storage and follow OAuth
	//    best practices, as outlined in OAuth 2.1, Section 7.1."
	//   "For public clients, authorization servers MUST rotate refresh tokens as
	//    described in OAuth 2.1 Section 4.3.1"
	// ============================================================================
	t.Run("refresh_token_security", func(t *testing.T) {
		clientID, _ := registerClient(t, "none")
		codeVerifier := cryptutil.NewRandomStringN(64)
		authCode := getAuthCode(t, clientID, codeVerifier)

		// Get initial tokens
		params := url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {authCode},
			"redirect_uri":  {"http://localhost:8080/callback"},
			"client_id":     {clientID},
			"code_verifier": {codeVerifier},
		}
		resp, result := doTokenRequest(t, params, nil)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		refreshToken := result["refresh_token"].(string)
		require.NotEmpty(t, refreshToken)

		t.Run("valid_refresh_succeeds", func(t *testing.T) {
			params := url.Values{
				"grant_type":    {"refresh_token"},
				"refresh_token": {refreshToken},
				"client_id":     {clientID},
			}
			resp, result := doTokenRequest(t, params, nil)
			assert.Equal(t, http.StatusOK, resp.StatusCode)
			assert.NotEmpty(t, result["access_token"])
			assert.NotEmpty(t, result["refresh_token"])
			// Store rotated token for next test
			refreshToken = result["refresh_token"].(string)
		})

		t.Run("revoked_refresh_token_fails", func(t *testing.T) {
			// Use the current refresh token to rotate it
			params := url.Values{
				"grant_type":    {"refresh_token"},
				"refresh_token": {refreshToken},
				"client_id":     {clientID},
			}
			resp1, result1 := doTokenRequest(t, params, nil)
			require.Equal(t, http.StatusOK, resp1.StatusCode)
			oldToken := refreshToken
			refreshToken = result1["refresh_token"].(string) // Get new rotated token

			// Now try to use the old (revoked) token
			params["refresh_token"] = []string{oldToken}
			resp2, result2 := doTokenRequest(t, params, nil)
			assert.Equal(t, http.StatusBadRequest, resp2.StatusCode)
			assert.Equal(t, "invalid_grant", result2["error"])
		})

		t.Run("refresh_token_for_different_client_fails", func(t *testing.T) {
			// Get a fresh refresh token for client1
			client1ID, _ := registerClient(t, "none")
			verifier := cryptutil.NewRandomStringN(64)
			code := getAuthCode(t, client1ID, verifier)
			params := url.Values{
				"grant_type":    {"authorization_code"},
				"code":          {code},
				"redirect_uri":  {"http://localhost:8080/callback"},
				"client_id":     {client1ID},
				"code_verifier": {verifier},
			}
			resp, result := doTokenRequest(t, params, nil)
			require.Equal(t, http.StatusOK, resp.StatusCode)
			client1RefreshToken := result["refresh_token"].(string)

			// Register a different client
			client2ID, _ := registerClient(t, "none")

			// Try to use client1's refresh token with client2
			params = url.Values{
				"grant_type":    {"refresh_token"},
				"refresh_token": {client1RefreshToken},
				"client_id":     {client2ID},
			}
			resp, result = doTokenRequest(t, params, nil)
			assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
			assert.Equal(t, "invalid_grant", result["error"])
		})

		t.Run("malformed_refresh_token_fails", func(t *testing.T) {
			params := url.Values{
				"grant_type":    {"refresh_token"},
				"refresh_token": {"not-a-valid-refresh-token-at-all"},
				"client_id":     {clientID},
			}
			resp, result := doTokenRequest(t, params, nil)
			assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
			assert.Equal(t, "invalid_grant", result["error"])
		})
	})

	// ============================================================================
	// Test #5: Access Token Validation
	// MCP Authorization Spec (2025-11-25):
	//   "MCP servers MUST validate access tokens as described in OAuth 2.1 Section 5.2"
	//   "MCP servers MUST validate that access tokens were issued specifically for
	//    them as the intended audience"
	//   "Invalid or expired tokens MUST receive a HTTP 401 response"
	// ============================================================================
	t.Run("access_token_validation", func(t *testing.T) {
		t.Run("missing_token_returns_401_with_www_authenticate", func(t *testing.T) {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, mcpServerURL, nil)
			require.NoError(t, err)
			resp, err := baseHTTPClient().Do(req)
			require.NoError(t, err)
			defer resp.Body.Close()

			assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
			wwwAuth := resp.Header.Get("WWW-Authenticate")
			assert.Contains(t, wwwAuth, "Bearer")
			assert.Contains(t, wwwAuth, "resource_metadata")
		})

		t.Run("invalid_token_returns_401", func(t *testing.T) {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, mcpServerURL, nil)
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer invalid-garbage-token")
			resp, err := baseHTTPClient().Do(req)
			require.NoError(t, err)
			defer resp.Body.Close()

			assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		})

		t.Run("valid_token_succeeds", func(t *testing.T) {
			// Get a valid token
			clientID, _ := registerClient(t, "none")
			codeVerifier := cryptutil.NewRandomStringN(64)
			authCode := getAuthCode(t, clientID, codeVerifier)
			params := url.Values{
				"grant_type":    {"authorization_code"},
				"code":          {authCode},
				"redirect_uri":  {"http://localhost:8080/callback"},
				"client_id":     {clientID},
				"code_verifier": {codeVerifier},
			}
			_, result := doTokenRequest(t, params, nil)
			accessToken := result["access_token"].(string)

			// Use it to connect to MCP server
			mcpClient := mcp.NewClient(&mcp.Implementation{
				Name:    "conformance-client",
				Version: "1.0.0",
			}, nil)
			httpClient := upstreams.NewHTTPClient(env.ServerCAs(), &upstreams.RequestOptions{})
			httpClient.Transport = &tokenTransport{base: httpClient.Transport, token: accessToken}

			session, err := mcpClient.Connect(ctx, &mcp.StreamableClientTransport{
				Endpoint:   mcpServerURL,
				HTTPClient: httpClient,
			}, nil)
			require.NoError(t, err)
			defer session.Close()

			result2, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "ping"})
			require.NoError(t, err)
			require.NotEmpty(t, result2.Content)
		})
	})
}
