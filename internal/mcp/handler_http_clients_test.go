package mcp

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/config"
)

// TestNewSharesClientMetadataClient checks that handlers rebuilt on config
// change fetch client metadata documents with the process-wide SSRF-safe
// client.
func TestNewSharesClientMetadataClient(t *testing.T) {
	t.Parallel()

	cfg := config.New(config.NewDefaultOptions())
	h1, err := New(t.Context(), DefaultPrefix, cfg, nil, http.DefaultClient)
	require.NoError(t, err)
	h2, err := New(t.Context(), DefaultPrefix, cfg, nil, http.DefaultClient)
	require.NoError(t, err)

	assert.Same(t, ssrfSafeClient(), h1.clientMetadataFetcher.httpClient)
	assert.Same(t, ssrfSafeClient(), h2.clientMetadataFetcher.httpClient)
}
