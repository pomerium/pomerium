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

// TestMCPRefreshAgainstRotatingIdP runs the refresh grant against an identity
// provider that invalidates a refresh token when it is presented and revokes the
// whole grant family if a consumed one is presented again, which is how Auth0,
// Okta and Entra behave.
//
// It covers two things the store exists for, through the whole deployed stack:
// the rotated token is written back, so a later grant presents the successor
// rather than a consumed token; and no token is ever presented twice, which on
// this provider would end the family. Presentation counts are asserted against
// the provider, because a grant served from the store's cache proves neither.
// accessTokenTTL is short enough to wait out between grants.
const accessTokenTTL = time.Second

func TestMCPRefreshAgainstRotatingIdP(t *testing.T) {
	env := testenv.New(t)

	env.Add(testenv.ModifierFunc(func(_ context.Context, cfg *config.Config) {
		enableMCP(cfg, true)
		cfg.Options.MCPAllowedClientIDDomains = []string{"*.localhost.pomerium.io"}
	}))

	idp := scenarios.NewIDP(
		[]*scenarios.User{{Email: "user@example.com"}},
		scenarios.WithRotationMode(scenarios.RotateReuseDetect),
		// Short enough that the stored access token can be allowed to expire
		// between grants below, which is what makes each of them a real
		// presentation. With the provider's usual hour the second grant would be
		// served from the store and the test would pass even with rotation
		// write-back broken.
		scenarios.WithAccessTokenTTL(accessTokenTTL),
	)
	env.Add(idp)

	mcpServer := mcp.NewServer(&mcp.Implementation{
		Name:    "rotating-idp-test-server",
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

	serverUpstream := upstreams.HTTP(nil, upstreams.WithDisplayName("MCP Rotating IdP Server"))
	serverHandler := mcp.NewStreamableHTTPHandler(func(_ *http.Request) *mcp.Server {
		return mcpServer
	}, nil)
	serverUpstream.Handle("/", serverHandler.ServeHTTP)

	serverRoute := serverUpstream.Route().
		From(env.SubdomainURL("mcp-rotating-idp")).
		Policy(func(p *config.Policy) {
			p.AllowedDomains = []string{"example.com"}
			p.MCP = &config.MCP{Server: &config.MCPServer{}}
		})
	env.AddUpstream(serverUpstream)

	env.Start()
	snippets.WaitStartupComplete(env)

	ctx := env.Context()
	parsedURL, err := url.Parse(serverRoute.URL().Value())
	require.NoError(t, err)

	newClient := func() *http.Client {
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
	resp, err := newClient().Do(req)
	require.NoError(t, err)
	var asMetadata mcphandler.AuthorizationServerMetadata
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&asMetadata))
	resp.Body.Close()

	const redirectURI = "http://localhost:8080/callback"
	clientID, _ := newDCRRegistrar(ctx, &asMetadata, newClient, redirectURI)(t, "none")

	// Complete an authorization to obtain the first pair of tokens.
	codeVerifier := cryptutil.NewRandomStringN(64)
	authParams := url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {redirectURI},
		"state":                 {cryptutil.NewRandomStringN(32)},
		"code_challenge":        {generateS256Challenge(codeVerifier)},
		"code_challenge_method": {"S256"},
	}
	authClient := upstreams.NewHTTPClient(env.ServerCAs(), &upstreams.RequestOptions{})
	authClient.Jar, _ = cookiejar.New(nil)
	authClient.CheckRedirect = func(req *http.Request, _ []*http.Request) error {
		if strings.HasPrefix(req.URL.String(), redirectURI) {
			return http.ErrUseLastResponse
		}
		return nil
	}
	req, err = http.NewRequestWithContext(ctx, http.MethodGet,
		asMetadata.AuthorizationEndpoint+"?"+authParams.Encode(), nil)
	require.NoError(t, err)
	authResp, err := upstreams.AuthenticateFlow(ctx, authClient, req, "user@example.com", false)
	require.NoError(t, err)
	authResp.Body.Close()
	authCode, _, _ := parseCallbackParams(t, authResp.Header.Get("Location"))
	require.NotEmpty(t, authCode)

	postToken := func(t *testing.T, params url.Values) (int, map[string]any) {
		t.Helper()
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, asMetadata.TokenEndpoint,
			strings.NewReader(params.Encode()))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := newClient().Do(req)
		require.NoError(t, err)
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		var result map[string]any
		_ = json.Unmarshal(body, &result)
		t.Logf("token response: status=%d body=%s", resp.StatusCode, string(body))
		return resp.StatusCode, result
	}

	status, tokens := postToken(t, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {authCode},
		"redirect_uri":  {redirectURI},
		"client_id":     {clientID},
		"code_verifier": {codeVerifier},
	})
	require.Equal(t, http.StatusOK, status)
	refreshToken, ok := tokens["refresh_token"].(string)
	require.True(t, ok && refreshToken != "")

	// The refresh grant asks the store for liveness checked within its debounce
	// window, so each of these grants goes upstream. On this provider a
	// presentation consumes the token, so a second grant can only succeed if the
	// rotated one was written back, and a replay would revoke the family.
	upstreamBefore := idp.RefreshCount()
	const grants = 2
	for i := range grants {
		// Let the stored access token expire, so this grant has to present
		// rather than be served from the canonical record.
		time.Sleep(accessTokenTTL + 500*time.Millisecond)

		status, result := postToken(t, url.Values{
			"grant_type":    {"refresh_token"},
			"refresh_token": {refreshToken},
			"client_id":     {clientID},
		})
		require.Equal(t, http.StatusOK, status,
			"refresh %d must succeed; a consumed upstream token means the rotation was not written back", i+1)
		assert.NotEmpty(t, result["access_token"])
		next, ok := result["refresh_token"].(string)
		require.True(t, ok && next != "")
		assert.NotEqual(t, refreshToken, next, "the downstream refresh token rotates too")
		refreshToken = next
	}

	presentations := idp.RefreshCount() - upstreamBefore
	assert.Equal(t, int64(grants), presentations,
		"each grant presents exactly once: fewer means a grant was served from the "+
			"store and proves nothing about rotation, more means a token was replayed")
	assert.Equal(t, 1, idp.ValidRefreshTokenCount(),
		"one valid upstream token remains: the chain rotated, nothing was stranded, "+
			"and reuse detection never fired")
}
