package mcp

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDomainMatcher_IsAllowed(t *testing.T) {
	tests := []struct {
		name           string
		allowedDomains []string
		hostname       string
		expected       bool
	}{
		{
			name:           "exact match",
			allowedDomains: []string{"vscode.dev", "github.com"},
			hostname:       "vscode.dev",
			expected:       true,
		},
		{
			name:           "exact match second domain",
			allowedDomains: []string{"vscode.dev", "github.com"},
			hostname:       "github.com",
			expected:       true,
		},
		{
			name:           "wildcard match",
			allowedDomains: []string{"*.github.com"},
			hostname:       "api.github.com",
			expected:       true,
		},
		{
			name:           "wildcard does not match nested subdomain",
			allowedDomains: []string{"*.github.com"},
			hostname:       "foo.api.github.com",
			expected:       false,
		},
		{
			name:           "wildcard does not match bare domain",
			allowedDomains: []string{"*.github.com"},
			hostname:       "github.com",
			expected:       false,
		},
		{
			name:           "no match",
			allowedDomains: []string{"vscode.dev"},
			hostname:       "evil.com",
			expected:       false,
		},
		{
			name:           "empty allowed list",
			allowedDomains: []string{},
			hostname:       "any.com",
			expected:       false,
		},
		{
			name:           "nil allowed list",
			allowedDomains: nil,
			hostname:       "any.com",
			expected:       false,
		},
		{
			name:           "partial match is not allowed",
			allowedDomains: []string{"github.com"},
			hostname:       "notgithub.com",
			expected:       false,
		},
		{
			name:           "subdomain of exact match not allowed",
			allowedDomains: []string{"github.com"},
			hostname:       "api.github.com",
			expected:       false,
		},
		{
			name:           "combined exact and wildcard",
			allowedDomains: []string{"vscode.dev", "*.github.com"},
			hostname:       "api.github.com",
			expected:       true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			matcher := NewDomainMatcher(tc.allowedDomains)
			assert.Equal(t, tc.expected, matcher.IsAllowed(tc.hostname))
		})
	}
}

func TestDomainMatcher_ValidateURLDomain(t *testing.T) {
	t.Run("allowed domain", func(t *testing.T) {
		matcher := NewDomainMatcher([]string{"vscode.dev", "*.github.com"})
		u, _ := url.Parse("https://vscode.dev/oauth/client.json")
		err := matcher.ValidateURLDomain(u)
		assert.NoError(t, err)
	})

	t.Run("allowed wildcard domain", func(t *testing.T) {
		matcher := NewDomainMatcher([]string{"vscode.dev", "*.github.com"})
		u, _ := url.Parse("https://api.github.com/oauth/client.json")
		err := matcher.ValidateURLDomain(u)
		assert.NoError(t, err)
	})

	t.Run("disallowed domain", func(t *testing.T) {
		matcher := NewDomainMatcher([]string{"vscode.dev", "*.github.com"})
		u, _ := url.Parse("https://evil.com/oauth/client.json")
		err := matcher.ValidateURLDomain(u)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrDomainNotAllowed)
		assert.Contains(t, err.Error(), "evil.com")
	})

	t.Run("hostname with port", func(t *testing.T) {
		matcher := NewDomainMatcher([]string{"vscode.dev"})
		u, _ := url.Parse("https://vscode.dev:8443/oauth/client.json")
		err := matcher.ValidateURLDomain(u)
		// Hostname() strips the port, so this should work
		assert.NoError(t, err)
	})
}
