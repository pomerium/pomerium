package mcp

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/config"
)

func TestUpstreamAuthHandler_OnConfigChange_RefreshesDomainMatcher(t *testing.T) {
	t.Parallel()

	old := &config.Config{Options: config.NewDefaultOptions()}
	old.Options.MCPAllowedASMetadataDomains = []string{"old.example.com"}

	h := NewUpstreamAuthHandler(
		nil,
		NewHostInfo(old, nil),
		nil,
		NewDomainMatcher(old.Options.GetMCPAllowedAsMetadataDomains()),
	)

	require.NoError(t, h.asMetadataDomainMatcher.Load().ValidateURLDomain(
		mustParseURL(t, "https://old.example.com/.well-known/oauth-authorization-server")))

	updated := &config.Config{Options: config.NewDefaultOptions()}
	updated.Options.MCPAllowedASMetadataDomains = []string{"new.example.com"}
	h.OnConfigChange(updated)

	matcher := h.asMetadataDomainMatcher.Load()
	assert.NoError(t, matcher.ValidateURLDomain(mustParseURL(t, "https://new.example.com/foo")))
	assert.ErrorIs(t,
		matcher.ValidateURLDomain(mustParseURL(t, "https://old.example.com/foo")),
		ErrDomainNotAllowed,
		"old.example.com must no longer be allowed after OnConfigChange")
}

func mustParseURL(t *testing.T, s string) *url.URL {
	t.Helper()
	u, err := url.Parse(s)
	require.NoError(t, err)
	return u
}
