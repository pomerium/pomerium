package mcp_test

import (
	"net/url"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/mcp"
)

func TestBuildOAuthConfig(t *testing.T) {
	cfg := &config.Config{
		Options: &config.Options{
			Policies: []config.Policy{
				{
					Name: "test",
					From: "https://regular.example.com",
				},
				{
					Name:        "mcp-1",
					Description: "description-1",
					LogoURL:     "https://logo.example.com",
					From:        "https://mcp1.example.com",
					MCP:         &config.MCP{Server: &config.MCPServer{}},
				},
				{
					Name: "mcp-2",
					From: "https://mcp2.example.com",
					MCP: &config.MCP{
						Server: &config.MCPServer{UpstreamOAuth2: &config.UpstreamOAuth2{
							ClientID:     "client_id",
							ClientSecret: "client_secret",
							Endpoint: config.OAuth2Endpoint{
								AuthURL:   "https://auth.example.com/auth",
								TokenURL:  "https://auth.example.com/token",
								AuthStyle: config.OAuth2EndpointAuthStyleInParams,
							},
						}},
					},
				},
				{
					Name: "mcp-client-1",
					From: "https://client1.example.com",
					MCP:  &config.MCP{Client: &config.MCPClient{}},
				},
				{
					Name: "mcp-client-2",
					From: "https://client2.example.com",
					MCP:  &config.MCP{Client: &config.MCPClient{}},
				},
			},
		},
	}
	gotServers, gotClients := mcp.BuildHostInfo(cfg, "/prefix")

	expectedServers := map[string]mcp.ServerHostInfo{
		"mcp1.example.com": {
			Name:        "mcp-1",
			Host:        "mcp1.example.com",
			URL:         "https://mcp1.example.com",
			Description: "description-1",
			LogoURL:     "https://logo.example.com",
		},
		"mcp2.example.com": {
			Name: "mcp-2",
			Host: "mcp2.example.com",
			URL:  "https://mcp2.example.com",
			Config: &oauth2.Config{
				ClientID:     "client_id",
				ClientSecret: "client_secret",
				Endpoint: oauth2.Endpoint{
					AuthURL:   "https://auth.example.com/auth",
					TokenURL:  "https://auth.example.com/token",
					AuthStyle: oauth2.AuthStyleInParams,
				},
				RedirectURL: "https://mcp2.example.com/prefix/server/oauth/callback",
			},
		},
	}

	expectedClients := map[string]mcp.ClientHostInfo{
		"client1.example.com": {},
		"client2.example.com": {},
	}

	diff := cmp.Diff(gotServers, expectedServers, cmpopts.IgnoreUnexported(oauth2.Config{}))
	require.Empty(t, diff, "servers mismatch")

	diff = cmp.Diff(gotClients, expectedClients)
	require.Empty(t, diff, "clients mismatch")
}

func TestHostInfo_IsMCPClientForHost(t *testing.T) {
	cfg := &config.Config{
		Options: &config.Options{
			Policies: []config.Policy{
				{
					Name: "mcp-server",
					From: "https://server.example.com",
					MCP:  &config.MCP{Server: &config.MCPServer{}},
				},
				{
					Name: "mcp-client",
					From: "https://client.example.com",
					MCP:  &config.MCP{Client: &config.MCPClient{}},
				},
			},
		},
	}

	hostInfo := mcp.NewHostInfo(cfg, nil)

	require.True(t, hostInfo.IsMCPClientForHost("client.example.com"))
	require.False(t, hostInfo.IsMCPClientForHost("server.example.com"))
	require.False(t, hostInfo.IsMCPClientForHost("unknown.example.com"))
}

func TestNewServerHostInfoFromPolicy(t *testing.T) {
	tests := []struct {
		name        string
		policy      config.Policy
		want        mcp.ServerHostInfo
		wantErr     bool
		errContains string
	}{
		{
			name: "basic policy with default path",
			policy: config.Policy{
				Name:        "test-server",
				Description: "Test MCP server",
				LogoURL:     "https://example.com/logo.png",
				From:        "https://mcp.example.com",
				MCP:         &config.MCP{Server: &config.MCPServer{}},
			},
			want: mcp.ServerHostInfo{
				Name:        "test-server",
				Description: "Test MCP server",
				LogoURL:     "https://example.com/logo.png",
				Host:        "mcp.example.com",
				URL:         "https://mcp.example.com",
			},
			wantErr: false,
		},
		{
			name: "policy with custom path",
			policy: config.Policy{
				Name: "test-server-custom-path",
				From: "https://mcp.example.com",
				MCP: &config.MCP{Server: &config.MCPServer{
					Path: stringPtr("/api/mcp"),
				}},
			},
			want: mcp.ServerHostInfo{
				Name: "test-server-custom-path",
				Host: "mcp.example.com",
				URL:  "https://mcp.example.com/api/mcp",
			},
			wantErr: false,
		},
		{
			name: "policy with existing path in from URL",
			policy: config.Policy{
				Name: "test-server-existing-path",
				From: "https://mcp.example.com/existing",
				MCP:  &config.MCP{Server: &config.MCPServer{}},
			},
			want: mcp.ServerHostInfo{
				Name: "test-server-existing-path",
				Host: "mcp.example.com",
				URL:  "https://mcp.example.com/existing",
			},
			wantErr: false,
		},
		{
			name: "policy with existing path and custom path",
			policy: config.Policy{
				Name: "test-server-both-paths",
				From: "https://mcp.example.com/base",
				MCP: &config.MCP{Server: &config.MCPServer{
					Path: stringPtr("/api"),
				}},
			},
			want: mcp.ServerHostInfo{
				Name: "test-server-both-paths",
				Host: "mcp.example.com",
				URL:  "https://mcp.example.com/base/api",
			},
			wantErr: false,
		},
		{
			name: "policy with port in URL",
			policy: config.Policy{
				Name: "test-server-with-port",
				From: "https://mcp.example.com:8080",
				MCP:  &config.MCP{Server: &config.MCPServer{}},
			},
			want: mcp.ServerHostInfo{
				Name: "test-server-with-port",
				Host: "mcp.example.com",
				URL:  "https://mcp.example.com:8080",
			},
			wantErr: false,
		},
		{
			name: "policy with empty fields",
			policy: config.Policy{
				From: "https://minimal.example.com",
				MCP:  &config.MCP{Server: &config.MCPServer{}},
			},
			want: mcp.ServerHostInfo{
				Host: "minimal.example.com",
				URL:  "https://minimal.example.com",
			},
			wantErr: false,
		},
		{
			name: "invalid from URL",
			policy: config.Policy{
				Name: "invalid-url",
				From: "://invalid-url",
				MCP:  &config.MCP{Server: &config.MCPServer{}},
			},
			wantErr:     true,
			errContains: "failed to parse policy FROM URL",
		},
		{
			name: "policy with query parameters in from URL",
			policy: config.Policy{
				Name: "test-query-params",
				From: "https://mcp.example.com?param=value",
				MCP:  &config.MCP{Server: &config.MCPServer{}},
			},
			want: mcp.ServerHostInfo{
				Name: "test-query-params",
				Host: "mcp.example.com",
				URL:  "https://mcp.example.com?param=value",
			},
			wantErr: false,
		},
		{
			name: "policy with fragment in from URL",
			policy: config.Policy{
				Name: "test-fragment",
				From: "https://mcp.example.com#fragment",
				MCP:  &config.MCP{Server: &config.MCPServer{}},
			},
			want: mcp.ServerHostInfo{
				Name: "test-fragment",
				Host: "mcp.example.com",
				URL:  "https://mcp.example.com#fragment",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := mcp.NewServerHostInfoFromPolicy(&tt.policy)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					require.Contains(t, err.Error(), tt.errContains)
				}
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

// Helper function to create string pointers
func stringPtr(s string) *string {
	return &s
}

func TestHostInfo_UsesAutoDiscovery(t *testing.T) {
	cfg := &config.Config{
		Options: &config.Options{
			Policies: []config.Policy{
				{
					Name: "auto-discovery-server",
					From: "https://auto.example.com",
					MCP:  &config.MCP{Server: &config.MCPServer{}},
					// No UpstreamOAuth2 = auto-discovery mode
				},
				{
					Name: "upstream-oauth-server",
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
				{
					Name: "non-mcp-route",
					From: "https://regular.example.com",
					// No MCP config
				},
			},
		},
	}

	hostInfo := mcp.NewHostInfo(cfg, nil)

	tests := []struct {
		name     string
		host     string
		expected bool
	}{
		{
			name:     "auto-discovery host returns true",
			host:     "auto.example.com",
			expected: true,
		},
		{
			name:     "upstream oauth host returns false",
			host:     "upstream.example.com",
			expected: false,
		},
		{
			name:     "non-MCP host returns false",
			host:     "regular.example.com",
			expected: false,
		},
		{
			name:     "unknown host returns false",
			host:     "unknown.example.com",
			expected: false,
		},
		{
			name:     "empty host returns false",
			host:     "",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := hostInfo.UsesAutoDiscovery(tt.host)
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestHostInfo_GetServerHostInfo(t *testing.T) {
	cfg := &config.Config{
		Options: &config.Options{
			Policies: []config.Policy{
				{
					Name:        "test-server",
					Description: "Test MCP Server",
					LogoURL:     "https://logo.example.com/logo.png",
					From:        "https://mcp.example.com",
					MCP:         &config.MCP{Server: &config.MCPServer{}},
				},
				{
					Name: "non-mcp-route",
					From: "https://regular.example.com",
				},
			},
		},
	}

	hostInfo := mcp.NewHostInfo(cfg, nil)

	t.Run("returns info for MCP server host", func(t *testing.T) {
		info, ok := hostInfo.GetServerHostInfo("mcp.example.com")
		require.True(t, ok)
		require.Equal(t, "test-server", info.Name)
		require.Equal(t, "Test MCP Server", info.Description)
		require.Equal(t, "mcp.example.com", info.Host)
		require.Equal(t, "https://mcp.example.com", info.URL)
	})

	t.Run("returns false for non-MCP host", func(t *testing.T) {
		_, ok := hostInfo.GetServerHostInfo("regular.example.com")
		require.False(t, ok)
	})

	t.Run("returns false for unknown host", func(t *testing.T) {
		_, ok := hostInfo.GetServerHostInfo("unknown.example.com")
		require.False(t, ok)
	})

	t.Run("returns false for empty host", func(t *testing.T) {
		_, ok := hostInfo.GetServerHostInfo("")
		require.False(t, ok)
	})
}

func TestServerHostInfo_UpstreamURL(t *testing.T) {
	t.Run("populated from To config", func(t *testing.T) {
		toURL := mustParseURL(t, "https://api.upstream.com")
		policy := &config.Policy{
			Name: "test-server",
			From: "https://proxy.example.com",
			To:   config.WeightedURLs{{URL: toURL}},
			MCP:  &config.MCP{Server: &config.MCPServer{}},
		}

		info, err := mcp.NewServerHostInfoFromPolicy(policy)
		require.NoError(t, err)
		require.Equal(t, "https://api.upstream.com", info.UpstreamURL)
		require.Equal(t, "https://proxy.example.com", info.URL)
	})

	t.Run("includes server path", func(t *testing.T) {
		toURL := mustParseURL(t, "https://api.upstream.com")
		policy := &config.Policy{
			Name: "test-server",
			From: "https://proxy.example.com",
			To:   config.WeightedURLs{{URL: toURL}},
			MCP: &config.MCP{Server: &config.MCPServer{
				Path: stringPtr("/mcp"),
			}},
		}

		info, err := mcp.NewServerHostInfoFromPolicy(policy)
		require.NoError(t, err)
		require.Equal(t, "https://api.upstream.com/mcp", info.UpstreamURL)
		require.Equal(t, "https://proxy.example.com/mcp", info.URL)
	})

	t.Run("preserves To path and appends server path", func(t *testing.T) {
		toURL := mustParseURL(t, "https://api.upstream.com/v1")
		policy := &config.Policy{
			Name: "test-server",
			From: "https://proxy.example.com",
			To:   config.WeightedURLs{{URL: toURL}},
			MCP: &config.MCP{Server: &config.MCPServer{
				Path: stringPtr("/mcp"),
			}},
		}

		info, err := mcp.NewServerHostInfoFromPolicy(policy)
		require.NoError(t, err)
		require.Equal(t, "https://api.upstream.com/v1/mcp", info.UpstreamURL)
	})

	t.Run("empty when no To config", func(t *testing.T) {
		policy := &config.Policy{
			Name: "test-server",
			From: "https://proxy.example.com",
			MCP:  &config.MCP{Server: &config.MCPServer{}},
		}

		info, err := mcp.NewServerHostInfoFromPolicy(policy)
		require.NoError(t, err)
		require.Empty(t, info.UpstreamURL)
	})

	t.Run("available via GetServerHostInfo", func(t *testing.T) {
		toURL := mustParseURL(t, "https://api.upstream.com")
		cfg := &config.Config{
			Options: &config.Options{
				Policies: []config.Policy{
					{
						Name: "test-server",
						From: "https://proxy.example.com",
						To:   config.WeightedURLs{{URL: toURL}},
						MCP:  &config.MCP{Server: &config.MCPServer{}},
					},
				},
			},
		}

		hostInfo := mcp.NewHostInfo(cfg, nil)
		info, ok := hostInfo.GetServerHostInfo("proxy.example.com")
		require.True(t, ok)
		require.Equal(t, "https://api.upstream.com", info.UpstreamURL)
	})
}

func mustParseURL(t *testing.T, rawURL string) url.URL {
	t.Helper()
	u, err := url.Parse(rawURL)
	require.NoError(t, err)
	return *u
}
