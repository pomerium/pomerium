package mcp_test

import (
	"net/http"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/internal/mcp"
)

func TestWWWAuthenticate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		host        string
		requestPath string
		expected    string
	}{
		{
			name:        "root path",
			host:        "example.com",
			requestPath: "/",
			expected:    `Bearer resource_metadata="https://example.com/.well-known/oauth-protected-resource"`,
		},
		{
			name:        "empty path",
			host:        "example.com",
			requestPath: "",
			expected:    `Bearer resource_metadata="https://example.com/.well-known/oauth-protected-resource"`,
		},
		{
			name:        "path-based MCP server",
			host:        "example.com",
			requestPath: "/mcp",
			expected:    `Bearer resource_metadata="https://example.com/.well-known/oauth-protected-resource/mcp"`,
		},
		{
			name:        "nested path",
			host:        "example.com",
			requestPath: "/api/mcp/v1",
			expected:    `Bearer resource_metadata="https://example.com/.well-known/oauth-protected-resource/api/mcp/v1"`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			hdr := make(http.Header)
			err := mcp.SetWWWAuthenticateHeader(hdr, tc.host, tc.requestPath)
			require.NoError(t, err)
			require.Empty(t, cmp.Diff(hdr, http.Header{
				"Www-Authenticate": []string{tc.expected},
			}))
		})
	}
}
