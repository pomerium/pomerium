package e2e

import (
	"context"
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

// TestMCPCORSHeaders verifies CORS headers across all three layers of the MCP
// proxy stack as responses come out of Pomerium:
//
//  1. ext_authz layer (cors.go) — denied/preflight responses before reaching upstream
//  2. OAuth handler layer (handler.go) — successful requests to OAuth endpoints
//  3. Metadata handler layer (handler_metadata.go) — .well-known endpoints
//
// Spec references:
//   - OAuth 2.1 §3.2: token, registration, and metadata endpoints SHOULD support CORS;
//     authorization endpoint MUST NOT (accessed via redirect, not fetch).
//   - RFC 9700 (Protected Resource Metadata): metadata endpoints SHOULD support CORS.
//   - MCP Transport spec: servers MUST validate Origin on incoming connections;
//     CORS headers are required for browser-based MCP clients.
//   - RFC 8414 §3.3: the issuer in AS metadata MUST be identical to the
//     authorization server identifier discovered via protected resource metadata.
func TestMCPCORSHeaders(t *testing.T) {
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
		Name:    "cors-test-server",
		Version: "1.0.0",
	}, nil)
	mcp.AddTool(mcpServer, &mcp.Tool{
		Name:        "echo",
		Description: "Echoes input",
	}, func(_ context.Context, _ *mcp.CallToolRequest, _ any) (*mcp.CallToolResult, any, error) {
		return &mcp.CallToolResult{
			Content: []mcp.Content{
				&mcp.TextContent{Text: "echo"},
			},
		}, nil, nil
	})

	serverUpstream := upstreams.HTTP(nil, upstreams.WithDisplayName("MCP CORS Test Server"))
	serverHandler := mcp.NewStreamableHTTPHandler(func(_ *http.Request) *mcp.Server {
		return mcpServer
	}, nil)
	serverUpstream.Handle("/", serverHandler.ServeHTTP)

	serverRoute := serverUpstream.Route().
		From(env.SubdomainURL("mcp-cors-test")).
		Policy(func(p *config.Policy) {
			p.AllowedDomains = []string{"example.com"}
			p.MCP = &config.MCP{
				Server: &config.MCPServer{},
			}
		})
	env.AddUpstream(serverUpstream)

	env.Start()
	snippets.WaitStartupComplete(env)

	type testState struct {
		httpClient                *http.Client
		mcpServerURL              string
		protectedResourceMetadata mcphandler.ProtectedResourceMetadata
		asMetadata                mcphandler.AuthorizationServerMetadata
		clientID                  string
		accessToken               string
	}
	ts := &testState{}

	ctx := env.Context()

	// --- (a) Unauthenticated GET returns 401 with CORS + "Unauthorized" body ---
	// Validates the ext_authz CORS layer (cors.go) which sets CORS headers on
	// denied responses before the request reaches the upstream MCP server.
	// See: MCP Transport spec — browser-based clients need CORS on auth errors.
	t.Run("unauthenticated GET returns 401 with CORS", func(t *testing.T) {
		ts.httpClient = upstreams.NewHTTPClient(env.ServerCAs(), &upstreams.RequestOptions{})
		ts.httpClient.Jar, _ = cookiejar.New(nil)
		ts.httpClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		}

		ts.mcpServerURL = serverRoute.URL().Value()

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, ts.mcpServerURL, nil)
		require.NoError(t, err)
		req.Header.Set("Accept", "application/json")

		resp, err := ts.httpClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, "expected 401 for unauthenticated request")

		// Validate response body contains JSON error.
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		var jsonBody map[string]any
		require.NoError(t, json.Unmarshal(body, &jsonBody), "expected valid JSON body")
		assert.Equal(t, "Unauthorized", jsonBody["error"], "expected Unauthorized error in response body")

		// Validate ext_authz CORS headers (from cors.go SetCORSHeaders).
		assertExtAuthzCORSHeaders(t, resp.Header, "unauthenticated 401")

		// Validate WWW-Authenticate header with Bearer + resource_metadata (RFC 9728 §5).
		wwwAuth := resp.Header.Get("WWW-Authenticate")
		assert.NotEmpty(t, wwwAuth, "expected WWW-Authenticate header")
		assert.True(t, strings.HasPrefix(wwwAuth, "Bearer "),
			"WWW-Authenticate should start with Bearer scheme (RFC 9728 §5)")
		assert.Contains(t, wwwAuth, "resource_metadata=",
			"WWW-Authenticate should contain resource_metadata parameter (RFC 9728 §5)")
	})

	// --- (b) OPTIONS preflight returns 204 with CORS ---
	// Validates that preflight requests are handled by the ext_authz CORS layer
	// before reaching the upstream. This is essential for browser fetch() calls.
	t.Run("OPTIONS preflight returns 204 with CORS", func(t *testing.T) {
		req, err := http.NewRequestWithContext(ctx, http.MethodOptions, ts.mcpServerURL, nil)
		require.NoError(t, err)
		req.Header.Set("Origin", "http://localhost:5173")
		req.Header.Set("Access-Control-Request-Method", "POST")
		req.Header.Set("Access-Control-Request-Headers", "Authorization, Content-Type")

		resp, err := ts.httpClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusNoContent, resp.StatusCode,
			"OPTIONS preflight should return 204 No Content")

		assertExtAuthzCORSHeaders(t, resp.Header, "OPTIONS preflight")

		body, _ := io.ReadAll(resp.Body)
		assert.Empty(t, body, "OPTIONS preflight should have empty body")
	})

	// --- (c) Protected Resource Metadata endpoint has CORS ---
	// Validates the metadata handler CORS layer (handler_metadata.go).
	// RFC 9700 / OAuth 2.1 §3.2: metadata endpoints SHOULD support CORS.
	t.Run("protected resource metadata has CORS", func(t *testing.T) {
		// First, get the resource_metadata URL from the 401 response.
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, ts.mcpServerURL, nil)
		require.NoError(t, err)
		req.Header.Set("Accept", "application/json")
		resp, err := ts.httpClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		wwwAuth := resp.Header.Get("WWW-Authenticate")

		prmURL := parseResourceMetadataFromWWWAuthenticate(t, wwwAuth)
		require.NotEmpty(t, prmURL, "expected resource_metadata URL in WWW-Authenticate")

		// Fetch the protected resource metadata endpoint.
		// Origin header is required to trigger rs/cors middleware (standard browser behavior).
		req, err = http.NewRequestWithContext(ctx, http.MethodGet, prmURL, nil)
		require.NoError(t, err)
		req.Header.Set("Origin", "http://localhost:5173")
		resp, err = ts.httpClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)

		// CORS: metadata endpoints SHOULD support CORS (OAuth 2.1 §3.2).
		assertCORSHeaders(t, resp.Header, "protected resource metadata")

		// Validate metadata content (RFC 9728 §3).
		err = json.NewDecoder(resp.Body).Decode(&ts.protectedResourceMetadata)
		require.NoError(t, err)
		assert.NotEmpty(t, ts.protectedResourceMetadata.Resource,
			"resource field is REQUIRED (RFC 9728 §3)")
		assert.NotEmpty(t, ts.protectedResourceMetadata.AuthorizationServers,
			"authorization_servers should be present")

		// Verify the issuer in authorization_servers has no trailing slash.
		// This is important for RFC 8414 §3.3 issuer matching later.
		issuer := ts.protectedResourceMetadata.AuthorizationServers[0]
		assert.False(t, strings.HasSuffix(issuer, "/"),
			"issuer in authorization_servers should not have trailing slash (RFC 8414 §2 issuer format)")
	})

	// --- (d) Authorization Server Metadata endpoint has CORS ---
	// Validates the metadata handler CORS layer for AS metadata.
	// OAuth 2.1 §3.2: metadata endpoints SHOULD support CORS.
	// RFC 8414 §3.3: issuer in AS metadata MUST match the discovered identifier.
	t.Run("authorization server metadata has CORS", func(t *testing.T) {
		authServerIssuer := ts.protectedResourceMetadata.AuthorizationServers[0]
		asMetadataURL := authServerIssuer + mcphandler.WellKnownAuthorizationServerEndpoint

		// Origin header is required to trigger rs/cors middleware (standard browser behavior).
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, asMetadataURL, nil)
		require.NoError(t, err)
		req.Header.Set("Origin", "http://localhost:5173")
		resp, err := ts.httpClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)

		// CORS: metadata endpoints SHOULD support CORS (OAuth 2.1 §3.2).
		assertCORSHeaders(t, resp.Header, "authorization server metadata")

		err = json.NewDecoder(resp.Body).Decode(&ts.asMetadata)
		require.NoError(t, err)

		// RFC 8414 §3.3: the issuer in the metadata MUST be identical to
		// the authorization server identifier discovered from protected resource metadata.
		assert.Equal(t, authServerIssuer, ts.asMetadata.Issuer,
			"issuer in AS metadata must match authorization_servers entry (RFC 8414 §3.3)")
	})

	// --- (e) OAuth registration endpoint has CORS ---
	// Validates the OAuth handler CORS layer (handler.go).
	// OAuth 2.1 §3.2: registration endpoint SHOULD support CORS.
	t.Run("registration endpoint has CORS", func(t *testing.T) {
		clientMetadata := map[string]any{
			"redirect_uris":              []string{"http://localhost:5173/callback"},
			"client_name":                "CORS Test Client",
			"token_endpoint_auth_method": "none",
			"grant_types":                []string{"authorization_code"},
			"response_types":             []string{"code"},
		}
		clientMetadataJSON, err := json.Marshal(clientMetadata)
		require.NoError(t, err)

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, ts.asMetadata.RegistrationEndpoint,
			strings.NewReader(string(clientMetadataJSON)))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", "http://localhost:5173")

		resp, err := ts.httpClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)

		// CORS: registration endpoint SHOULD support CORS (OAuth 2.1 §3.2).
		assertCORSHeaders(t, resp.Header, "registration endpoint")

		var registrationResponse map[string]any
		err = json.NewDecoder(resp.Body).Decode(&registrationResponse)
		require.NoError(t, err)
		var ok bool
		ts.clientID, ok = registrationResponse["client_id"].(string)
		require.True(t, ok && ts.clientID != "", "expected client_id in registration response")
	})

	// --- (f) Authenticated request passes through to upstream ---
	// Validates that after completing the full OAuth flow, the MCP server is reachable.
	t.Run("authenticated request reaches upstream", func(t *testing.T) {
		codeVerifier := cryptutil.NewRandomStringN(64)
		codeChallenge := generateS256Challenge(codeVerifier)
		state := cryptutil.NewRandomStringN(32)
		redirectURI := "http://localhost:5173/callback"
		parsedMCPURL, err := url.Parse(ts.mcpServerURL)
		require.NoError(t, err)
		resource := (&url.URL{Scheme: "https", Host: parsedMCPURL.Host}).String()

		authParams := url.Values{
			"response_type":         {"code"},
			"client_id":             {ts.clientID},
			"redirect_uri":          {redirectURI},
			"state":                 {state},
			"code_challenge":        {codeChallenge},
			"code_challenge_method": {"S256"},
			"resource":              {resource},
		}
		authURL := ts.asMetadata.AuthorizationEndpoint + "?" + authParams.Encode()

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

		authCode, returnedState := parseCallbackParams(t, resp.Header.Get("Location"))
		require.NotEmpty(t, authCode, "expected authorization code")
		assert.Equal(t, state, returnedState, "state parameter should match")

		// Exchange code for token.
		tokenParams := url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {authCode},
			"redirect_uri":  {redirectURI},
			"client_id":     {ts.clientID},
			"code_verifier": {codeVerifier},
			"resource":      {resource},
		}
		tokenClient := upstreams.NewHTTPClient(env.ServerCAs(), &upstreams.RequestOptions{})
		tokenClient.Jar, _ = cookiejar.New(nil)
		req, err = http.NewRequestWithContext(ctx, http.MethodPost, ts.asMetadata.TokenEndpoint,
			strings.NewReader(tokenParams.Encode()))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err = tokenClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)

		var tokenResponse map[string]any
		body, _ := io.ReadAll(resp.Body)
		require.NoError(t, json.Unmarshal(body, &tokenResponse))
		var ok bool
		ts.accessToken, ok = tokenResponse["access_token"].(string)
		require.True(t, ok && ts.accessToken != "", "expected access_token")

		// Use the token to reach the upstream MCP server.
		req, err = http.NewRequestWithContext(ctx, http.MethodPost, ts.mcpServerURL, nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+ts.accessToken)
		req.Header.Set("Content-Type", "application/json")
		resp, err = ts.httpClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		// The MCP server should process the request (2xx) or return a valid
		// MCP/JSON-RPC response. A 401 would indicate the token wasn't accepted.
		assert.NotEqual(t, http.StatusUnauthorized, resp.StatusCode,
			"authenticated request should not return 401")
		assert.NotEqual(t, http.StatusForbidden, resp.StatusCode,
			"authenticated request should not return 403")
	})
}

// assertCORSHeaders checks that basic CORS headers are present in the response.
// This validates the minimum required for browser-based OAuth/metadata endpoints
// per OAuth 2.1 §3.2.
func assertCORSHeaders(t *testing.T, h http.Header, desc string) {
	t.Helper()
	assert.Equal(t, "*", h.Get("Access-Control-Allow-Origin"),
		"%s: Access-Control-Allow-Origin should be * (OAuth 2.1 §3.2)", desc)
}

// assertExtAuthzCORSHeaders checks the full set of CORS headers set by the
// ext_authz layer (cors.go SetCORSHeaders) on denied/preflight responses.
// These headers are needed by browser-based MCP clients (MCP Transport spec).
func assertExtAuthzCORSHeaders(t *testing.T, h http.Header, desc string) {
	t.Helper()
	assert.Equal(t, "*", h.Get("Access-Control-Allow-Origin"),
		"%s: Access-Control-Allow-Origin should be *", desc)
	assert.Contains(t, h.Get("Access-Control-Allow-Methods"), "POST",
		"%s: Access-Control-Allow-Methods should include POST", desc)
	assert.Contains(t, h.Get("Access-Control-Allow-Headers"), "Authorization",
		"%s: Access-Control-Allow-Headers should include Authorization", desc)
	assert.Contains(t, h.Get("Access-Control-Expose-Headers"), "WWW-Authenticate",
		"%s: Access-Control-Expose-Headers should include WWW-Authenticate (RFC 9728 §5)", desc)
	assert.Contains(t, h.Get("Vary"), "Origin",
		"%s: Vary should include Origin for cache-correctness", desc)
}
