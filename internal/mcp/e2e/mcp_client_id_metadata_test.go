package e2e

import (
	"context"
	"crypto/tls"
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

// TestMCPClientIDMetadataDocument tests authorization flow using Client ID Metadata Documents
// as specified in draft-ietf-oauth-client-id-metadata-document-00.
// Instead of Dynamic Client Registration (RFC 7591), clients can use an HTTPS URL as their client_id.
// The URL points to a JSON document containing client metadata.
func TestMCPClientIDMetadataDocument(t *testing.T) {
	env := testenv.New(t)

	env.Add(testenv.ModifierFunc(func(_ context.Context, cfg *config.Config) {
		if cfg.Options.RuntimeFlags == nil {
			cfg.Options.RuntimeFlags = make(config.RuntimeFlags)
		}
		cfg.Options.RuntimeFlags[config.RuntimeFlagMCP] = true
		// Allow testenv domains for testing - in production this should be restricted
		cfg.Options.MCPAllowedClientIDDomains = []string{"*.localhost.pomerium.io"}
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
		From(env.SubdomainURL("mcp-clientid-test")).
		Policy(func(p *config.Policy) {
			p.AllowedDomains = []string{"example.com"}
			p.MCP = &config.MCP{
				Server: &config.MCPServer{},
			}
		})
	env.AddUpstream(serverUpstream)

	// Create a mock client metadata document server with a publicly accessible route (allow any)
	clientMetadataUpstream := upstreams.HTTP(nil, upstreams.WithDisplayName("Client Metadata Server"))
	clientMetadataRoute := clientMetadataUpstream.Route().
		From(env.SubdomainURL("client-metadata")).
		PPL(`- allow:
    or:
      - accept: true`)
	env.AddUpstream(clientMetadataUpstream)

	env.Start()
	snippets.WaitStartupComplete(env)

	// Configure an HTTP client for the metadata fetcher that trusts the test CA
	mcphandler.DefaultHTTPClient = &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: env.ServerCAs(),
			},
		},
	}
	t.Cleanup(func() {
		mcphandler.DefaultHTTPClient = nil
	})

	type testState struct {
		httpClient                *http.Client
		mcpServerURL              string
		parsedMCPURL              *url.URL
		protectedResourceMetadata mcphandler.ProtectedResourceMetadata
		asMetadata                mcphandler.AuthorizationServerMetadata
		clientID                  string // This is a URL pointing to the client metadata document
		codeVerifier              string
		state                     string
		redirectURI               string
		authCode                  string
		accessToken               string
	}
	ts := &testState{}

	ctx := env.Context()

	t.Run("step 1: verify authorization server metadata advertises client_id_metadata_document_supported", func(t *testing.T) {
		ts.httpClient = upstreams.NewHTTPClient(env.ServerCAs(), &upstreams.RequestOptions{})
		ts.httpClient.Jar, _ = cookiejar.New(nil)
		ts.httpClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		}

		ts.mcpServerURL = serverRoute.URL().Value()
		var err error
		ts.parsedMCPURL, err = url.Parse(ts.mcpServerURL)
		require.NoError(t, err)

		// Fetch authorization server metadata
		asMetadataURL := "https://" + ts.parsedMCPURL.Host + mcphandler.WellKnownAuthorizationServerEndpoint

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, asMetadataURL, nil)
		require.NoError(t, err)
		resp, err := ts.httpClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)

		// Unmarshal to a map to check for client_id_metadata_document_supported
		var metadataMap map[string]any
		err = json.NewDecoder(resp.Body).Decode(&metadataMap)
		require.NoError(t, err)

		// Verify client_id_metadata_document_supported is advertised (per draft-ietf-oauth-client-id-metadata-document Section 5)
		supported, ok := metadataMap["client_id_metadata_document_supported"].(bool)
		require.True(t, ok, "client_id_metadata_document_supported should be present in AS metadata")
		assert.True(t, supported, "client_id_metadata_document_supported should be true")

		// Store AS metadata for later steps
		ts.asMetadata.AuthorizationEndpoint, _ = metadataMap["authorization_endpoint"].(string)
		ts.asMetadata.TokenEndpoint, _ = metadataMap["token_endpoint"].(string)
		t.Logf("AS Metadata: authorization_endpoint=%s, token_endpoint=%s", ts.asMetadata.AuthorizationEndpoint, ts.asMetadata.TokenEndpoint)
	})

	t.Run("step 2: fetch protected resource metadata", func(t *testing.T) {
		resourceMetadataURL := "https://" + ts.parsedMCPURL.Host + mcphandler.WellKnownProtectedResourceEndpoint

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, resourceMetadataURL, nil)
		require.NoError(t, err)
		resp, err := ts.httpClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)

		err = json.NewDecoder(resp.Body).Decode(&ts.protectedResourceMetadata)
		require.NoError(t, err)
		require.NotEmpty(t, ts.protectedResourceMetadata.Resource)
	})

	t.Run("step 3: setup client metadata document server", func(t *testing.T) {
		// The client_id is the URL pointing to the client metadata document
		// This is the key difference from Dynamic Client Registration
		clientMetadataBaseURL := clientMetadataRoute.URL().Value()
		ts.clientID = clientMetadataBaseURL + "/oauth/client-metadata.json"
		ts.redirectURI = "http://127.0.0.1:8080/callback"

		// Setup the client metadata document endpoint
		clientMetadataUpstream.Handle("/oauth/client-metadata.json", func(w http.ResponseWriter, _ *http.Request) {
			metadata := map[string]any{
				// client_id MUST match the URL exactly (per draft Section 4.1)
				"client_id":                  ts.clientID,
				"client_name":                "Test MCP Client via Metadata Document",
				"client_uri":                 clientMetadataBaseURL,
				"redirect_uris":              []string{ts.redirectURI, "http://localhost:8080/callback"},
				"grant_types":                []string{"authorization_code"},
				"response_types":             []string{"code"},
				"token_endpoint_auth_method": "none",
			}
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "max-age=3600")
			_ = json.NewEncoder(w).Encode(metadata)
		})

		t.Logf("Client ID (metadata document URL): %s", ts.clientID)
		t.Logf("Redirect URI: %s", ts.redirectURI)
	})

	t.Run("step 4: authorization request with URL-based client_id", func(t *testing.T) {
		ts.codeVerifier = cryptutil.NewRandomStringN(64)
		codeChallenge := generateS256Challenge(ts.codeVerifier)
		ts.state = cryptutil.NewRandomStringN(32)

		authParams := url.Values{
			"response_type":         {"code"},
			"client_id":             {ts.clientID}, // URL-based client_id
			"redirect_uri":          {ts.redirectURI},
			"state":                 {ts.state},
			"code_challenge":        {codeChallenge},
			"code_challenge_method": {"S256"},
			"resource":              {ts.protectedResourceMetadata.Resource},
		}

		authURL := ts.asMetadata.AuthorizationEndpoint + "?" + authParams.Encode()
		t.Logf("Authorization URL with URL-based client_id: %s", authURL)

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

		var returnedState string
		ts.authCode, returnedState = parseCallbackParams(t, resp.Header.Get("Location"))
		require.NotEmpty(t, ts.authCode, "expected authorization code")
		assert.Equal(t, ts.state, returnedState, "state parameter should match")
		t.Logf("Received authorization code: %s", ts.authCode)
	})

	t.Run("step 5: exchange authorization code for token", func(t *testing.T) {
		tokenParams := url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {ts.authCode},
			"redirect_uri":  {ts.redirectURI},
			"client_id":     {ts.clientID}, // URL-based client_id
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
	})

	t.Run("step 6: use access token for MCP requests", func(t *testing.T) {
		mcpClient := mcp.NewClient(&mcp.Implementation{
			Name:    "test-client",
			Version: "1.0.0",
		}, nil)

		mcpHTTPClient := upstreams.NewHTTPClient(env.ServerCAs(), &upstreams.RequestOptions{})
		mcpHTTPClient.Transport = &tokenTransport{
			base:  mcpHTTPClient.Transport,
			token: ts.accessToken,
		}

		session, err := mcpClient.Connect(ctx, &mcp.StreamableClientTransport{
			Endpoint:   ts.mcpServerURL,
			HTTPClient: mcpHTTPClient,
		}, nil)
		require.NoError(t, err)
		defer session.Close()

		result, err := session.CallTool(ctx, &mcp.CallToolParams{
			Name: "hello",
		})
		require.NoError(t, err)
		require.NotEmpty(t, result.Content)
		t.Logf("MCP tool call successful with URL-based client_id: %+v", result.Content)
	})
}

// TestMCPClientIDMetadataDocumentValidation tests validation of client metadata documents.
func TestMCPClientIDMetadataDocumentValidation(t *testing.T) {
	env := testenv.New(t)

	env.Add(testenv.ModifierFunc(func(_ context.Context, cfg *config.Config) {
		if cfg.Options.RuntimeFlags == nil {
			cfg.Options.RuntimeFlags = make(config.RuntimeFlags)
		}
		cfg.Options.RuntimeFlags[config.RuntimeFlagMCP] = true
		// Allow testenv domains for testing - in production this should be restricted
		cfg.Options.MCPAllowedClientIDDomains = []string{"*.localhost.pomerium.io"}
	}))

	idp := scenarios.NewIDP([]*scenarios.User{
		{Email: "user@example.com"},
	})
	env.Add(idp)

	mcpServer := mcp.NewServer(&mcp.Implementation{
		Name:    "test-server",
		Version: "1.0.0",
	}, nil)

	serverUpstream := upstreams.HTTP(nil, upstreams.WithDisplayName("MCP Server"))
	serverHandler := mcp.NewStreamableHTTPHandler(func(_ *http.Request) *mcp.Server {
		return mcpServer
	}, nil)
	serverUpstream.Handle("/", serverHandler.ServeHTTP)

	serverRoute := serverUpstream.Route().
		From(env.SubdomainURL("mcp-validation-test")).
		Policy(func(p *config.Policy) {
			p.AllowedDomains = []string{"example.com"}
			p.MCP = &config.MCP{
				Server: &config.MCPServer{},
			}
		})
	env.AddUpstream(serverUpstream)

	clientMetadataUpstream := upstreams.HTTP(nil, upstreams.WithDisplayName("Client Metadata Server"))
	clientMetadataRoute := clientMetadataUpstream.Route().
		From(env.SubdomainURL("client-metadata-val")).
		PPL(`- allow:
    or:
      - accept: true`)
	env.AddUpstream(clientMetadataUpstream)

	env.Start()
	snippets.WaitStartupComplete(env)

	mcphandler.DefaultHTTPClient = &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: env.ServerCAs(),
			},
		},
	}
	t.Cleanup(func() {
		mcphandler.DefaultHTTPClient = nil
	})

	ctx := env.Context()

	mcpServerURL := serverRoute.URL().Value()
	parsedMCPURL, err := url.Parse(mcpServerURL)
	require.NoError(t, err)

	clientMetadataBaseURL := clientMetadataRoute.URL().Value()

	httpClient := upstreams.NewHTTPClient(env.ServerCAs(), &upstreams.RequestOptions{})
	httpClient.Jar, _ = cookiejar.New(nil)
	httpClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}

	asMetadataURL := "https://" + parsedMCPURL.Host + mcphandler.WellKnownAuthorizationServerEndpoint
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, asMetadataURL, nil)
	require.NoError(t, err)
	resp, err := httpClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	var asMetadata mcphandler.AuthorizationServerMetadata
	err = json.NewDecoder(resp.Body).Decode(&asMetadata)
	require.NoError(t, err)

	t.Run("reject authorization when redirect_uri not in metadata", func(t *testing.T) {
		clientID := clientMetadataBaseURL + "/oauth/mismatch-client.json"

		// Setup metadata with limited redirect URIs
		clientMetadataUpstream.Handle("/oauth/mismatch-client.json", func(w http.ResponseWriter, _ *http.Request) {
			metadata := map[string]any{
				"client_id":                  clientID,
				"client_name":                "Mismatch Test Client",
				"redirect_uris":              []string{"http://allowed-uri.example.com/callback"},
				"grant_types":                []string{"authorization_code"},
				"response_types":             []string{"code"},
				"token_endpoint_auth_method": "none",
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(metadata)
		})

		authParams := url.Values{
			"response_type":         {"code"},
			"client_id":             {clientID},
			"redirect_uri":          {"http://evil-attacker.com/callback"}, // Not in metadata
			"state":                 {"test-state"},
			"code_challenge":        {generateS256Challenge("test-verifier")},
			"code_challenge_method": {"S256"},
		}

		authURL := asMetadata.AuthorizationEndpoint + "?" + authParams.Encode()

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, authURL, nil)
		require.NoError(t, err)

		authClient := upstreams.NewHTTPClient(env.ServerCAs(), &upstreams.RequestOptions{})
		authClient.Jar, _ = cookiejar.New(nil)

		resp, err := upstreams.AuthenticateFlow(ctx, authClient, req, "user@example.com", false)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.True(t, resp.StatusCode >= 400,
			"expected error response for invalid redirect_uri, got %d", resp.StatusCode)
		t.Logf("Response status for mismatched redirect_uri: %d", resp.StatusCode)
	})

	t.Run("reject when client_id in document doesn't match URL", func(t *testing.T) {
		clientID := clientMetadataBaseURL + "/oauth/wrong-id-client.json"

		// Setup metadata where client_id doesn't match the URL
		clientMetadataUpstream.Handle("/oauth/wrong-id-client.json", func(w http.ResponseWriter, _ *http.Request) {
			metadata := map[string]any{
				"client_id":                  "https://different-url.example.com/client.json", // Doesn't match!
				"client_name":                "Wrong ID Test Client",
				"redirect_uris":              []string{"http://127.0.0.1:8080/callback"},
				"grant_types":                []string{"authorization_code"},
				"response_types":             []string{"code"},
				"token_endpoint_auth_method": "none",
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(metadata)
		})

		authParams := url.Values{
			"response_type":         {"code"},
			"client_id":             {clientID},
			"redirect_uri":          {"http://127.0.0.1:8080/callback"},
			"state":                 {"test-state"},
			"code_challenge":        {generateS256Challenge("test-verifier")},
			"code_challenge_method": {"S256"},
		}

		authURL := asMetadata.AuthorizationEndpoint + "?" + authParams.Encode()

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, authURL, nil)
		require.NoError(t, err)

		authClient := upstreams.NewHTTPClient(env.ServerCAs(), &upstreams.RequestOptions{})
		authClient.Jar, _ = cookiejar.New(nil)

		resp, err := upstreams.AuthenticateFlow(ctx, authClient, req, "user@example.com", false)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Should be rejected - client_id mismatch
		assert.True(t, resp.StatusCode >= 400,
			"expected error response for client_id mismatch, got %d", resp.StatusCode)
		t.Logf("Response status for client_id mismatch: %d", resp.StatusCode)
	})
}
