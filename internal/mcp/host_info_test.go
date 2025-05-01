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
			},
		},
	}
	got := mcp.BuildHostInfo(cfg, "/prefix")
	diff := cmp.Diff(got, map[string]mcp.HostInfo{
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
	}, cmpopts.IgnoreUnexported(oauth2.Config{}))
	require.Empty(t, diff)
}
