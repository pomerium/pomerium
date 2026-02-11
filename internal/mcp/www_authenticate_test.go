package mcp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseWWWAuthenticate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected *WWWAuthenticateParams
	}{
		{
			name:     "empty string returns nil",
			input:    "",
			expected: nil,
		},
		{
			name:     "non-Bearer scheme returns nil",
			input:    `Basic realm="example"`,
			expected: nil,
		},
		{
			name:     "Bearer only without params returns empty params",
			input:    "Bearer ",
			expected: &WWWAuthenticateParams{},
		},
		{
			name:  "resource_metadata only",
			input: `Bearer resource_metadata="https://upstream/.well-known/oauth-protected-resource"`,
			expected: &WWWAuthenticateParams{
				ResourceMetadata: "https://upstream/.well-known/oauth-protected-resource",
			},
		},
		{
			name:  "all parameters",
			input: `Bearer realm="mcp-server", resource_metadata="https://upstream/.well-known/oauth-protected-resource", scope="mcp:read mcp:write", error="insufficient_scope", error_description="Token does not have required scope"`,
			expected: &WWWAuthenticateParams{
				Realm:            "mcp-server",
				ResourceMetadata: "https://upstream/.well-known/oauth-protected-resource",
				Scope:            []string{"mcp:read", "mcp:write"},
				Error:            "insufficient_scope",
				ErrorDescription: "Token does not have required scope",
			},
		},
		{
			name:  "scope with single value",
			input: `Bearer scope="mcp:admin"`,
			expected: &WWWAuthenticateParams{
				Scope: []string{"mcp:admin"},
			},
		},
		{
			name:  "insufficient_scope error without scope param",
			input: `Bearer error="insufficient_scope"`,
			expected: &WWWAuthenticateParams{
				Error: "insufficient_scope",
			},
		},
		{
			name:  "round-trip with SetWWWAuthenticateHeader output",
			input: `Bearer resource_metadata="https://example.com/.well-known/oauth-protected-resource"`,
			expected: &WWWAuthenticateParams{
				ResourceMetadata: "https://example.com/.well-known/oauth-protected-resource",
			},
		},
		{
			name:  "non-string SFV values are silently skipped",
			input: `Bearer resource_metadata="https://example.com", max_age=3600`,
			expected: &WWWAuthenticateParams{
				ResourceMetadata: "https://example.com",
			},
		},
		{
			name:     "malformed SFV returns nil",
			input:    `Bearer !!!invalid`,
			expected: nil,
		},
		{
			name:     "case sensitive Bearer prefix",
			input:    `bearer resource_metadata="https://example.com"`,
			expected: nil, // "bearer" != "Bearer"
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			result := ParseWWWAuthenticate(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}
