package mcp

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/config"
)

// TestUpstreamAuthHandler_OnConfigChange_RefreshesDomainMatcher is the RED
// test for review finding I1.
//
// Before I1, NewUpstreamAuthHandlerFromConfig captured MCPAllowedASMetadataDomains
// once into an *DomainMatcher field and OnConfigChange only refreshed the host
// index. A Zero-delivered Options update that changed the allowlist would be
// silently ignored by ext_proc — same class of bug as the one the PR is
// already fixing for HostInfo.
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

	// Sanity: startup allowlist is in force.
	require.NotNil(t, h.asMetadataDomainMatcher.Load())
	require.NoError(t, h.asMetadataDomainMatcher.Load().ValidateURLDomain(mustParseURL(t, "https://old.example.com/.well-known/oauth-authorization-server")))

	// Config update swaps the allowlist (simulates a Zero-delivered Options change).
	updated := &config.Config{Options: config.NewDefaultOptions()}
	updated.Options.MCPAllowedASMetadataDomains = []string{"new.example.com"}
	h.OnConfigChange(updated)

	matcher := h.asMetadataDomainMatcher.Load()
	require.NotNil(t, matcher)
	assert.NoError(t, matcher.ValidateURLDomain(mustParseURL(t, "https://new.example.com/foo")),
		"new.example.com must be allowed after OnConfigChange")
	assert.ErrorIs(t, matcher.ValidateURLDomain(mustParseURL(t, "https://old.example.com/foo")), ErrDomainNotAllowed,
		"old.example.com must no longer be allowed — stale matcher would incorrectly pass this")
}

func mustParseURL(t *testing.T, s string) *url.URL {
	t.Helper()
	u, err := url.Parse(s)
	require.NoError(t, err)
	return u
}
