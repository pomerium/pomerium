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
	"time"

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

// TestMCPAccessTokenExpiry covers the part of the "refresh token security"
// conformance surface that the shared runMCPConformance env can't exercise: it
// needs its own, very short access token lifetime, whereas the conformance env
// runs many subtests against one shared server and can't tolerate a global TTL
// short enough to expire mid-test.
//
// internal/mcp has no per-handler-instance option hook reachable from the test
// environment for this (mcp.WithAccessTokenTTL is only ever applied by
// proxy.go's own call to mcp.New, with no test seam to override it) — but the
// access token TTL defaults to cfg.Options.CookieExpire (see
// internal/mcp/handler.go's New), and nothing in the proxy path overrides that
// default. So this test controls it the same way production does: via config.
func TestMCPAccessTokenExpiry(t *testing.T) {
	const accessTokenTTL = 2 * time.Second

	env := testenv.New(t)

	env.Add(testenv.ModifierFunc(func(_ context.Context, cfg *config.Config) {
		if cfg.Options.RuntimeFlags == nil {
			cfg.Options.RuntimeFlags = make(config.RuntimeFlags)
		}
		cfg.Options.RuntimeFlags[config.RuntimeFlagMCP] = true
		cfg.Options.RuntimeFlags[config.RuntimeFlagMCPDynamicClientRegistration] = true
		cfg.Options.MCPAllowedClientIDDomains = []string{"*.localhost.pomerium.io"}
		// The MCP access token TTL defaults to CookieExpire; this is what
		// stands in for mcp.WithAccessTokenTTL here (see comment above).
		cfg.Options.CookieExpire = accessTokenTTL
	}))

	idp := scenarios.NewIDP([]*scenarios.User{
		{Email: "user@example.com"},
	})
	env.Add(idp)

	mcpServer := mcp.NewServer(&mcp.Implementation{
		Name:    "access-token-expiry-test-server",
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

	serverUpstream := upstreams.HTTP(nil, upstreams.WithDisplayName("MCP Access Token Expiry Server"))
	serverHandler := mcp.NewStreamableHTTPHandler(func(_ *http.Request) *mcp.Server {
		return mcpServer
	}, nil)
	serverUpstream.Handle("/", serverHandler.ServeHTTP)

	serverRoute := serverUpstream.Route().
		From(env.SubdomainURL("mcp-access-token-expiry")).
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

	asMetadataURL := "https://" + parsedURL.Host + mcphandler.WellKnownAuthorizationServerEndpoint
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, asMetadataURL, nil)
	require.NoError(t, err)
	resp, err := baseHTTPClient().Do(req)
	require.NoError(t, err)
	var asMetadata mcphandler.AuthorizationServerMetadata
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&asMetadata))
	resp.Body.Close()

	const redirectURI = "http://localhost:8080/callback"

	// Register a public client via DCR.
	clientMetadata := map[string]any{
		"redirect_uris":              []string{redirectURI},
		"client_name":                "Access Token Expiry Test Client",
		"token_endpoint_auth_method": "none",
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
	}
	body, err := json.Marshal(clientMetadata)
	require.NoError(t, err)
	regReq, err := http.NewRequestWithContext(ctx, http.MethodPost, asMetadata.RegistrationEndpoint, strings.NewReader(string(body)))
	require.NoError(t, err)
	regReq.Header.Set("Content-Type", "application/json")
	regResp, err := baseHTTPClient().Do(regReq)
	require.NoError(t, err)
	defer regResp.Body.Close()
	require.Equal(t, http.StatusOK, regResp.StatusCode)
	var regResult map[string]any
	require.NoError(t, json.NewDecoder(regResp.Body).Decode(&regResult))
	clientID, _ := regResult["client_id"].(string)
	require.NotEmpty(t, clientID)

	codeVerifier := cryptutil.NewRandomStringN(64)
	codeChallenge := generateS256Challenge(codeVerifier)
	state := cryptutil.NewRandomStringN(32)

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
	authReq, err := http.NewRequestWithContext(ctx, http.MethodGet, authURL, nil)
	require.NoError(t, err)
	authResp, err := upstreams.AuthenticateFlow(ctx, authClient, authReq, "user@example.com", false)
	require.NoError(t, err)
	defer authResp.Body.Close()
	authCode, _, _ := parseCallbackParams(t, authResp.Header.Get("Location"))
	require.NotEmpty(t, authCode)

	doTokenRequest := func(params url.Values) (*http.Response, map[string]any) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, asMetadata.TokenEndpoint, strings.NewReader(params.Encode()))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := baseHTTPClient().Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		respBody, _ := io.ReadAll(resp.Body)
		var result map[string]any
		_ = json.Unmarshal(respBody, &result)
		t.Logf("Token response: status=%d body=%s", resp.StatusCode, string(respBody))
		return resp, result
	}

	tokenParams := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {authCode},
		"redirect_uri":  {redirectURI},
		"client_id":     {clientID},
		"code_verifier": {codeVerifier},
	}
	resp, result := doTokenRequest(tokenParams)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	accessToken, _ := result["access_token"].(string)
	require.NotEmpty(t, accessToken)
	refreshToken, _ := result["refresh_token"].(string)
	require.NotEmpty(t, refreshToken)

	t.Run("expired_access_token_refresh_succeeds", func(t *testing.T) {
		// Wait past the access token's TTL. It carries its own expiry
		// independent of the underlying session's, so this alone must not
		// affect the session or its refresh token.
		time.Sleep(accessTokenTTL + 2*time.Second)

		mcpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, mcpServerURL, nil)
		require.NoError(t, err)
		mcpReq.Header.Set("Authorization", "Bearer "+accessToken)
		mcpResp, err := baseHTTPClient().Do(mcpReq)
		require.NoError(t, err)
		defer mcpResp.Body.Close()
		assert.Equal(t, http.StatusUnauthorized, mcpResp.StatusCode, "expired access token must be rejected")

		refreshParams := url.Values{
			"grant_type":    {"refresh_token"},
			"refresh_token": {refreshToken},
			"client_id":     {clientID},
		}
		refreshResp, refreshResult := doTokenRequest(refreshParams)
		require.Equal(t, http.StatusOK, refreshResp.StatusCode, "refresh must succeed even though the access token has expired")
		newAccessToken, _ := refreshResult["access_token"].(string)
		require.NotEmpty(t, newAccessToken)

		mcpClient := mcp.NewClient(&mcp.Implementation{
			Name:    "access-token-expiry-client",
			Version: "1.0.0",
		}, nil)
		httpClient := upstreams.NewHTTPClient(env.ServerCAs(), &upstreams.RequestOptions{})
		httpClient.Transport = &tokenTransport{base: httpClient.Transport, token: newAccessToken}

		session, err := mcpClient.Connect(ctx, &mcp.StreamableClientTransport{
			Endpoint:   mcpServerURL,
			HTTPClient: httpClient,
		}, nil)
		require.NoError(t, err, "the newly refreshed access token must work")
		defer session.Close()

		result2, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "ping"})
		require.NoError(t, err)
		require.NotEmpty(t, result2.Content)
	})
}
