package e2e

import (
	"encoding/base64"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/testenv/upstreams"
)

// TestMCPUpgradeRejected verifies that a WebSocket upgrade request to an MCP
// server route that allows WebSocket upgrades is answered 400.
func TestMCPUpgradeRejected(t *testing.T) {
	srv := startMCPEchoOnlyServer(t, upstreams.DialHTTP1, func(p *config.Policy) { p.AllowWebsockets = true })

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.url, nil)
	require.NoError(t, err)
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Mcp-Session-Id", srv.session.ID())
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("Sec-WebSocket-Key", base64.StdEncoding.EncodeToString(make([]byte, 16)))
	resp, err := srv.httpClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}
