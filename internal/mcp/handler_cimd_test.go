package mcp

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/config"
)

func TestGenerateClientIDMetadata(t *testing.T) {
	cfg := &config.Config{
		Options: &config.Options{
			Policies: []config.Policy{
				{
					Name: "Auto Discovery Route",
					From: "https://auto.example.com",
					MCP:  &config.MCP{Server: &config.MCPServer{}},
					// No UpstreamOAuth2 = auto-discovery mode
				},
				{
					Name: "Upstream OAuth Route",
					From: "https://upstream.example.com",
					MCP: &config.MCP{
						Server: &config.MCPServer{
							UpstreamOAuth2: &config.UpstreamOAuth2{
								ClientID:     "client_id",
								ClientSecret: "client_secret",
								Endpoint: config.OAuth2Endpoint{
									AuthURL:  "https://auth.example.com/auth",
									TokenURL: "https://auth.example.com/token",
								},
							},
						},
					},
				},
			},
		},
	}

	hostInfo := NewHostInfo(cfg, nil)
	handler := &Handler{
		hosts: hostInfo,
	}

	t.Run("generates CIMD for auto-discovery host", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "https://auto.example.com/.pomerium/mcp/client/metadata.json", nil)
		req.Host = "auto.example.com"

		doc, ok := handler.generateClientIDMetadata(req)
		require.True(t, ok)
		require.NotNil(t, doc)

		assert.Equal(t, "https://auto.example.com/.pomerium/mcp/client/metadata.json", doc.ClientID)
		assert.Equal(t, "Auto Discovery Route", doc.ClientName)
		assert.Equal(t, "https://auto.example.com", doc.ClientURI)
		assert.Contains(t, doc.RedirectURIs, "https://auto.example.com/.pomerium/mcp/client/oauth/callback")
		assert.Equal(t, []string{"authorization_code", "refresh_token"}, doc.GrantTypes)
		assert.Equal(t, []string{"code"}, doc.ResponseTypes)
		assert.Equal(t, "none", doc.TokenEndpointAuthMethod)
	})

	t.Run("returns false for upstream OAuth host", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "https://upstream.example.com/.pomerium/mcp/client/metadata.json", nil)
		req.Host = "upstream.example.com"

		doc, ok := handler.generateClientIDMetadata(req)
		assert.False(t, ok)
		assert.Nil(t, doc)
	})

	t.Run("returns false for unknown host", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "https://unknown.example.com/.pomerium/mcp/client/metadata.json", nil)
		req.Host = "unknown.example.com"

		doc, ok := handler.generateClientIDMetadata(req)
		assert.False(t, ok)
		assert.Nil(t, doc)
	})

	t.Run("returns false for empty host", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "https://example.com/.pomerium/mcp/client/metadata.json", nil)
		req.Host = ""

		doc, ok := handler.generateClientIDMetadata(req)
		assert.False(t, ok)
		assert.Nil(t, doc)
	})

	t.Run("handles host with port", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "https://auto.example.com:8443/.pomerium/mcp/client/metadata.json", nil)
		req.Host = "auto.example.com:8443"

		doc, ok := handler.generateClientIDMetadata(req)
		require.True(t, ok)
		require.NotNil(t, doc)

		// client_id should include the port to match the actual document URL
		assert.Equal(t, "https://auto.example.com:8443/.pomerium/mcp/client/metadata.json", doc.ClientID)
		assert.Contains(t, doc.RedirectURIs, "https://auto.example.com:8443/.pomerium/mcp/client/oauth/callback")
	})

	t.Run("uses default client name when route name is empty", func(t *testing.T) {
		cfgNoName := &config.Config{
			Options: &config.Options{
				Policies: []config.Policy{
					{
						// No Name set
						From: "https://noname.example.com",
						MCP:  &config.MCP{Server: &config.MCPServer{}},
					},
				},
			},
		}

		hostInfoNoName := NewHostInfo(cfgNoName, nil)
		handlerNoName := &Handler{
			hosts: hostInfoNoName,
		}

		req := httptest.NewRequest(http.MethodGet, "https://noname.example.com/.pomerium/mcp/client/metadata.json", nil)
		req.Host = "noname.example.com"

		doc, ok := handlerNoName.generateClientIDMetadata(req)
		require.True(t, ok)
		require.NotNil(t, doc)

		// Should use default generated name
		assert.Equal(t, "Pomerium MCP Proxy - noname.example.com", doc.ClientName)
	})
}

func TestClientIDMetadataHandler(t *testing.T) {
	cfg := &config.Config{
		Options: &config.Options{
			Policies: []config.Policy{
				{
					Name: "Test Route",
					From: "https://auto.example.com",
					MCP:  &config.MCP{Server: &config.MCPServer{}},
				},
			},
		},
	}

	hostInfo := NewHostInfo(cfg, nil)
	handler := &Handler{
		hosts: hostInfo,
	}

	t.Run("returns 200 with valid CIMD for auto-discovery host", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "https://auto.example.com/.pomerium/mcp/client/metadata.json", nil)
		req.Host = "auto.example.com"
		rr := httptest.NewRecorder()

		handler.ClientIDMetadata(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))
		assert.Contains(t, rr.Header().Get("Cache-Control"), "max-age=")
	})

	t.Run("returns 404 for non-eligible host", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "https://unknown.example.com/.pomerium/mcp/client/metadata.json", nil)
		req.Host = "unknown.example.com"
		rr := httptest.NewRecorder()

		handler.ClientIDMetadata(rr, req)

		assert.Equal(t, http.StatusNotFound, rr.Code)
	})
}
