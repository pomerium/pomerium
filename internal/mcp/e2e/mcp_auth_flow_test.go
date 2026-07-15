package e2e

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/shogo82148/go-sfv"
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

// TestMCPAuthorizationFlow tests the complete MCP authorization flow
func TestMCPAuthorizationFlow(t *testing.T) {
	for _, mode := range registrationModes {
		t.Run(mode.name, func(t *testing.T) {
			runMCPAuthorizationFlow(t, mode)
		})
	}
}

func runMCPAuthorizationFlow(t *testing.T, mode registrationMode) {
	env := testenv.New(t)

	env.Add(testenv.ModifierFunc(func(_ context.Context, cfg *config.Config) {
		enableMCP(cfg, mode.dcr)
		cfg.Options.MCPAllowedClientIDDomains = []string{"*.localhost.pomerium.io"}
		if !mode.dcr {
			// CIMD fetches reach test servers on localhost.
			cfg.Options.InsecureSkipMCPMetadataSSRFCheck = true
		}
	}))

	idp := scenarios.NewIDP([]*scenarios.User{
		{Email: "user@example.com"},
	})
	env.Add(idp)

	mcpServer := mcp.NewServer(&mcp.Implementation{
		Name:    "test-server",
		Version: "1.0.0",
	}, nil)
	mcp.AddTool(mcpServer, &mcp.Tool{
		Name:        "hello",
		Description: "Returns a greeting",
	}, func(_ context.Context, _ *mcp.CallToolRequest, _ any) (*mcp.CallToolResult, any, error) {
		return &mcp.CallToolResult{
			Content: []mcp.Content{
				&mcp.TextContent{Text: "Hello from MCP Server!"},
			},
		}, nil, nil
	})

	serverUpstream := upstreams.HTTP(nil, upstreams.WithDisplayName("MCP Server"))
	serverHandler := mcp.NewStreamableHTTPHandler(func(_ *http.Request) *mcp.Server {
		return mcpServer
	}, nil)
	serverUpstream.Handle("/", serverHandler.ServeHTTP)

	serverRoute := serverUpstream.Route().
		From(env.SubdomainURL("mcp-auth-test-" + mode.name)).
		Policy(func(p *config.Policy) {
			p.AllowedDomains = []string{"example.com"}
			p.MCP = &config.MCP{
				Server: &config.MCPServer{},
			}
		})
	env.AddUpstream(serverUpstream)

	// In CIMD mode the client registers by hosting a metadata document on a
	// publicly accessible upstream rather than via the /register endpoint.
	var clientMetadataUpstream upstreams.HTTPUpstream
	var clientMetadataBaseURL func() string
	if !mode.dcr {
		clientMetadataUpstream = upstreams.HTTP(nil, upstreams.WithDisplayName("Client Metadata Server"))
		route := clientMetadataUpstream.Route().
			From(env.SubdomainURL("client-metadata-auth-" + mode.name)).
			PPL(`- allow:
    or:
      - accept: true`)
		env.AddUpstream(clientMetadataUpstream)
		clientMetadataBaseURL = func() string { return route.URL().Value() }
	}

	env.Start()
	snippets.WaitStartupComplete(env)

	type testState struct {
		httpClient                *http.Client
		mcpServerURL              string
		parsedMCPURL              *url.URL
		wwwAuth                   string
		protectedResourceMetadata mcphandler.ProtectedResourceMetadata
		asMetadata                mcphandler.AuthorizationServerMetadata
		clientID                  string
		codeVerifier              string
		state                     string
		redirectURI               string
		authCode                  string
		accessToken               string // validated in step 6
		refreshToken              string // validated in step 6
	}
	ts := &testState{}

	ctx := env.Context()

	t.Run("step 1: unauthenticated request returns 401", func(t *testing.T) {
		ts.httpClient = upstreams.NewHTTPClient(env.ServerCAs(), &upstreams.RequestOptions{})
		ts.httpClient.Jar, _ = cookiejar.New(nil)
		ts.httpClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		}

		ts.mcpServerURL = serverRoute.URL().Value()
		var err error
		ts.parsedMCPURL, err = url.Parse(ts.mcpServerURL)
		require.NoError(t, err)

		var resp *http.Response
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, ts.mcpServerURL, nil)
		require.NoError(t, err)
		resp, err = ts.httpClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, "expected 401 for unauthenticated request")
		ts.wwwAuth = resp.Header.Get("WWW-Authenticate")
		assert.NotEmpty(t, ts.wwwAuth, "expected WWW-Authenticate header in 401 response")
		t.Logf("WWW-Authenticate header: %s", ts.wwwAuth)
	})

	t.Run("step 2: fetch protected resource metadata (RFC 9728)", func(t *testing.T) {
		resourceMetadataURL := parseResourceMetadataFromWWWAuthenticate(t, ts.wwwAuth)
		require.NotEmpty(t, resourceMetadataURL, "expected resource_metadata URL in WWW-Authenticate header")

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, resourceMetadataURL, nil)
		require.NoError(t, err)
		resp, err := ts.httpClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)

		err = json.NewDecoder(resp.Body).Decode(&ts.protectedResourceMetadata)
		require.NoError(t, err)
		t.Logf("Protected Resource Metadata: %+v", ts.protectedResourceMetadata)

		require.NotEmpty(t, ts.protectedResourceMetadata.AuthorizationServers, "expected authorization_servers in metadata")
		t.Logf("Authorization Server Issuer: %s", ts.protectedResourceMetadata.AuthorizationServers[0])
	})

	t.Run("step 3: fetch authorization server metadata (RFC 8414)", func(t *testing.T) {
		authServerIssuer := ts.protectedResourceMetadata.AuthorizationServers[0]
		asMetadataURL := authServerIssuer + mcphandler.WellKnownAuthorizationServerEndpoint

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, asMetadataURL, nil)
		require.NoError(t, err)
		resp, err := ts.httpClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)

		err = json.NewDecoder(resp.Body).Decode(&ts.asMetadata)
		require.NoError(t, err)
		t.Logf("Authorization Server Metadata: %+v", ts.asMetadata)

		// registration_endpoint is advertised only when downstream DCR is enabled.
		if mode.dcr {
			require.NotEmpty(t, ts.asMetadata.RegistrationEndpoint, "expected registration_endpoint when DCR enabled")
		} else {
			require.Empty(t, ts.asMetadata.RegistrationEndpoint, "registration_endpoint must not be advertised when DCR disabled")
		}
		require.NotEmpty(t, ts.asMetadata.AuthorizationEndpoint, "expected authorization_endpoint")
		require.NotEmpty(t, ts.asMetadata.TokenEndpoint, "expected token_endpoint")
		require.Contains(t, ts.asMetadata.CodeChallengeMethodsSupported, "S256", "expected S256 PKCE support")

		// RFC 8414 §3.3: the issuer in the metadata MUST be identical to the
		// authorization server identifier the client discovered (authorization_servers[0]).
		require.Equal(t, authServerIssuer, ts.asMetadata.Issuer,
			"issuer in AS metadata must match authorization_servers entry from protected resource metadata")

		// RFC 9207: the AS advertises that it includes the iss parameter in
		// authorization responses so clients know to validate it.
		require.True(t, ts.asMetadata.AuthorizationResponseISSParameterSupported,
			"AS metadata must advertise authorization_response_iss_parameter_supported (RFC 9207)")
	})

	t.Run("step 4: client registration", func(t *testing.T) {
		const redirectURI = "http://localhost:8080/callback"
		var register clientRegistrar
		if mode.dcr {
			register = newDCRRegistrar(ctx, &ts.asMetadata, func() *http.Client { return ts.httpClient }, redirectURI)
		} else {
			register = newCIMDRegistrar(clientMetadataUpstream, clientMetadataBaseURL(), redirectURI)
		}
		ts.clientID, _ = register(t, "none")
		require.NotEmpty(t, ts.clientID, "expected client_id from registration")
		t.Logf("Registered client_id: %s", ts.clientID)
	})

	t.Run("step 5: authorization with PKCE", func(t *testing.T) {
		ts.codeVerifier = cryptutil.NewRandomStringN(64)
		codeChallenge := generateS256Challenge(ts.codeVerifier)
		ts.state = cryptutil.NewRandomStringN(32)
		ts.redirectURI = "http://localhost:8080/callback"

		authParams := url.Values{
			"response_type":         {"code"},
			"client_id":             {ts.clientID},
			"redirect_uri":          {ts.redirectURI},
			"state":                 {ts.state},
			"code_challenge":        {codeChallenge},
			"code_challenge_method": {"S256"},
			"resource":              {ts.protectedResourceMetadata.Resource},
		}

		authURL := ts.asMetadata.AuthorizationEndpoint + "?" + authParams.Encode()
		t.Logf("Authorization URL: %s", authURL)

		authClient := upstreams.NewHTTPClient(env.ServerCAs(), &upstreams.RequestOptions{})
		authClient.Jar, _ = cookiejar.New(nil)
		authClient.CheckRedirect = func(req *http.Request, _ []*http.Request) error {
			if strings.HasPrefix(req.URL.String(), ts.redirectURI) {
				return http.ErrUseLastResponse
			}
			return nil
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, authURL, nil)
		require.NoError(t, err)

		resp, err := upstreams.AuthenticateFlow(ctx, authClient, req, "user@example.com", false)
		require.NoError(t, err)
		defer resp.Body.Close()

		var returnedState, returnedIss string
		ts.authCode, returnedState, returnedIss = parseCallbackParams(t, resp.Header.Get("Location"))
		require.NotEmpty(t, ts.authCode, "expected authorization code")
		assert.Equal(t, ts.state, returnedState, "state parameter should match")

		// RFC 9207 / SEP-2468: the AS MUST include the iss parameter in the
		// authorization response, and it MUST equal the recorded issuer so the
		// client can validate it before redeeming the code.
		assert.Equal(t, ts.asMetadata.Issuer, returnedIss,
			"authorization response iss must match the AS metadata issuer (RFC 9207)")
		t.Logf("Received authorization code: %s (iss=%s)", ts.authCode, returnedIss)
	})

	t.Run("step 6: exchange authorization code for token", func(t *testing.T) {
		tokenParams := url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {ts.authCode},
			"redirect_uri":  {ts.redirectURI},
			"client_id":     {ts.clientID},
			"code_verifier": {ts.codeVerifier},
			"resource":      {ts.protectedResourceMetadata.Resource},
		}

		authClient := upstreams.NewHTTPClient(env.ServerCAs(), &upstreams.RequestOptions{})
		authClient.Jar, _ = cookiejar.New(nil)

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, ts.asMetadata.TokenEndpoint,
			strings.NewReader(tokenParams.Encode()))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := authClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)
		t.Logf("Token response status: %d, body: %s", resp.StatusCode, string(body))
		require.Equal(t, http.StatusOK, resp.StatusCode, "expected 200 for token request")

		var tokenResponse map[string]any
		err = json.Unmarshal(body, &tokenResponse)
		require.NoError(t, err)

		var ok bool
		ts.accessToken, ok = tokenResponse["access_token"].(string)
		require.True(t, ok && ts.accessToken != "", "expected access_token in response")
		t.Logf("Access token obtained (length: %d)", len(ts.accessToken))

		ts.refreshToken, ok = tokenResponse["refresh_token"].(string)
		require.True(t, ok && ts.refreshToken != "", "expected refresh_token in response")
		t.Logf("Refresh token obtained (length: %d)", len(ts.refreshToken))

		tokenType, _ := tokenResponse["token_type"].(string)
		assert.Equal(t, "Bearer", tokenType, "expected Bearer token type")
	})

	// NOTE: Refresh token and access token usage tests have been moved to
	// mcp_conformance_test.go which provides comprehensive coverage of:
	// - Refresh token rotation and revocation
	// - Cross-client refresh token attacks
	// - Malformed token handling
	// - Valid/invalid access token handling
}

func generateS256Challenge(verifier string) string {
	hash := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

func parseResourceMetadataFromWWWAuthenticate(t *testing.T, header string) string {
	t.Helper()

	if !strings.HasPrefix(header, "Bearer ") {
		return ""
	}

	dict, err := sfv.DecodeDictionary([]string{strings.TrimPrefix(header, "Bearer ")})
	if err != nil {
		return ""
	}

	for _, member := range dict {
		if member.Key == "resource_metadata" {
			if s, ok := member.Item.Value.(string); ok {
				return s
			}
		}
	}
	return ""
}

func parseCallbackParams(t *testing.T, callbackURL string) (code, state, iss string) {
	t.Helper()
	t.Logf("Parsing callback URL: %s", callbackURL)

	parsed, err := url.Parse(callbackURL)
	require.NoError(t, err)

	code = parsed.Query().Get("code")
	state = parsed.Query().Get("state")
	iss = parsed.Query().Get("iss")
	return code, state, iss
}
