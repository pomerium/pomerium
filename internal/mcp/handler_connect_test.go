package mcp

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAppendConnectError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		redirectURL string
		description string
		expected    string
	}{
		{
			name:        "appends error to simple URL",
			redirectURL: "https://example.com/.pomerium/routes",
			description: "discovery failed",
			expected:    "https://example.com/.pomerium/routes?connect_error=discovery+failed",
		},
		{
			name:        "appends error to URL with existing query params",
			redirectURL: "https://example.com/.pomerium/routes?foo=bar",
			description: "upstream error",
			expected:    "https://example.com/.pomerium/routes?connect_error=upstream+error&foo=bar",
		},
		{
			name:        "returns original on unparseable URL",
			redirectURL: "://invalid",
			description: "error",
			expected:    "://invalid",
		},
		{
			name:        "encodes special characters in description",
			redirectURL: "https://example.com/routes",
			description: `client_id domain not allowed: "auth.example.com"`,
			expected:    `https://example.com/routes?connect_error=client_id+domain+not+allowed%3A+%22auth.example.com%22`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := appendConnectError(tt.redirectURL, tt.description)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestCheckClientRedirectURL(t *testing.T) {
	t.Parallel()

	// Minimal handler with a HostInfo that has known MCP clients.
	srv := &Handler{
		hosts: &HostInfo{
			servers: map[string]ServerHostInfo{},
			clients: map[string]ClientHostInfo{
				"mcp-client.example.com": {},
			},
		},
	}
	// Mark buildOnce as done so it doesn't try to rebuild from nil config.
	srv.hosts.buildOnce.Do(func() {})

	tests := []struct {
		name        string
		requestHost string // Host header on the incoming request
		redirectURL string // redirect_url query parameter
		wantErr     bool
		wantURL     string
	}{
		{
			name:        "missing redirect_url",
			requestHost: "server.example.com",
			redirectURL: "",
			wantErr:     true,
		},
		{
			name:        "non-https scheme",
			requestHost: "server.example.com",
			redirectURL: "http://mcp-client.example.com/callback",
			wantErr:     true,
		},
		{
			name:        "no host in redirect_url",
			requestHost: "server.example.com",
			redirectURL: "https:///callback",
			wantErr:     true,
		},
		{
			name:        "valid MCP client host",
			requestHost: "server.example.com",
			redirectURL: "https://mcp-client.example.com/callback",
			wantErr:     false,
			wantURL:     "https://mcp-client.example.com/callback",
		},
		{
			name:        "unknown third-party host",
			requestHost: "server.example.com",
			redirectURL: "https://evil.example.com/callback",
			wantErr:     true,
		},
		{
			name:        "same host as request (portal redirect)",
			requestHost: "server.example.com",
			redirectURL: "https://server.example.com/.pomerium/routes",
			wantErr:     false,
			wantURL:     "https://server.example.com/.pomerium/routes",
		},
		{
			name:        "same host with port on request only",
			requestHost: "server.example.com:443",
			redirectURL: "https://server.example.com/.pomerium/routes",
			wantErr:     false,
			wantURL:     "https://server.example.com/.pomerium/routes",
		},
		{
			name:        "same host with port on redirect only",
			requestHost: "server.example.com",
			redirectURL: "https://server.example.com:443/.pomerium/routes",
			wantErr:     false,
			wantURL:     "https://server.example.com:443/.pomerium/routes",
		},
		{
			name:        "same host with matching ports",
			requestHost: "server.example.com:8443",
			redirectURL: "https://server.example.com:8443/.pomerium/routes",
			wantErr:     false,
			wantURL:     "https://server.example.com:8443/.pomerium/routes",
		},
		{
			name:        "same hostname with different ports matches (stripPort normalizes)",
			requestHost: "server.example.com:8443",
			redirectURL: "https://server.example.com:9443/.pomerium/routes",
			wantErr:     false,
			wantURL:     "https://server.example.com:9443/.pomerium/routes",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "https://"+tt.requestHost+"/.pomerium/mcp/connect", nil)
			r.Host = tt.requestHost
			if tt.redirectURL != "" {
				q := r.URL.Query()
				q.Set("redirect_url", tt.redirectURL)
				r.URL.RawQuery = q.Encode()
			}

			gotURL, err := srv.checkClientRedirectURL(r)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.wantURL, gotURL)
			}
		})
	}
}
