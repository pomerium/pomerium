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
					MCP:         &config.MCP{},
				},
				{
					Name: "mcp-2",
					From: "https://mcp2.example.com",
					MCP: &config.MCP{
						UpstreamOAuth2: &config.UpstreamOAuth2{
							ClientID:     "client_id",
							ClientSecret: "client_secret",
							Endpoint: config.OAuth2Endpoint{
								AuthURL:   "https://auth.example.com/auth",
								TokenURL:  "https://auth.example.com/token",
								AuthStyle: config.OAuth2EndpointAuthStyleInParams,
							},
						},
					},
				},
				{
					Name: "mcp-client-1",
					From: "https://client1.example.com",
					MCP: &config.MCP{
						PassUpstreamAccessToken: true,
					},
				},
				{
					Name: "mcp-client-2",
					From: "https://client2.example.com",
					MCP: &config.MCP{
						PassUpstreamAccessToken: true,
					},
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
					MCP:  &config.MCP{},
				},
				{
					Name: "mcp-client",
					From: "https://client.example.com",
					MCP: &config.MCP{
						PassUpstreamAccessToken: true,
					},
				},
			},
		},
	}

	hostInfo := mcp.NewHostInfo(cfg, nil)

	require.True(t, hostInfo.IsMCPClientForHost("client.example.com"))
	require.False(t, hostInfo.IsMCPClientForHost("server.example.com"))
	require.False(t, hostInfo.IsMCPClientForHost("unknown.example.com"))
}
