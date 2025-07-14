package mcp_test

import (
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
				RedirectURL: "https://mcp2.example.com/prefix/oauth/callback",
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
