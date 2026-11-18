package mcp

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/config"
)

// TestNewSharesHTTPClients checks that handlers rebuilt on config change share
// their HTTP clients.
func TestNewSharesHTTPClients(t *testing.T) {
	t.Parallel()

	cfg := config.New(config.NewDefaultOptions())
	h1, err := New(t.Context(), DefaultPrefix, cfg, nil)
	require.NoError(t, err)
	h2, err := New(t.Context(), DefaultPrefix, cfg, nil)
	require.NoError(t, err)

	assert.Same(t, h1.httpClient, h2.httpClient, "should share the upstream client")
	assert.Same(t, h1.clientMetadataFetcher.httpClient, h2.clientMetadataFetcher.httpClient,
		"should share the client metadata client")
}
