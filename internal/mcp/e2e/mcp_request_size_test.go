package e2e

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/internal/testenv/upstreams"
)

// TestMCPOversizedToolCallFailsClosed verifies that a tools/call whose body
// exceeds the route's max_request_bytes is rejected with 413 and never
// forwarded to the upstream, while one at the limit passes through intact, for
// each HTTP version the downstream client may speak.
func TestMCPOversizedToolCallFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name  string
		proto upstreams.Protocol
	}{
		{"http1", upstreams.DialHTTP1},
		{"http2", upstreams.DialHTTP2},
		{"http3", upstreams.DialHTTP3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			testMCPOversizedToolCallFailsClosed(t, tc.proto)
		})
	}
}

func testMCPOversizedToolCallFailsClosed(t *testing.T, proto upstreams.Protocol) {
	srv := startMCPEchoOnlyServer(t, proto)
	ctx := t.Context()

	res, err := srv.session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "echo",
		Arguments: map[string]any{"message": "hi"},
	})
	require.NoError(t, err, "small permitted tool call should succeed")
	require.NotEmpty(t, res.Content)

	_, err = srv.session.CallTool(ctx, &mcp.CallToolParams{Name: "hello"})
	require.Error(t, err, "small forbidden tool call should be denied")
	require.Zero(t, srv.helloCalls.Load())

	// postToolCall sends a tools/call padded with leading whitespace to exactly
	// size bytes, so a prefix of an oversized body is not valid JSON.
	postToolCall := func(exchange string, size int, name string, args map[string]any) (int, bodySizes) {
		t.Helper()
		params := map[string]any{"name": name}
		if args != nil {
			params["arguments"] = args
		}
		body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": exchange, "method": "tools/call", "params": params})
		require.NoError(t, err)
		require.LessOrEqual(t, len(body), size)
		body = append(bytes.Repeat([]byte(" "), size-len(body)), body...)
		return srv.post(ctx, t, exchange, body, srv.protocolVersion())
	}

	maxRequestBytes := int(srv.config.GetMaxRequestBytes())

	status, atClient := postToolCall("at-limit", maxRequestBytes, "echo", map[string]any{"message": "hi"})
	assert.Equal(t, http.StatusOK, status, "permitted tool call at max_request_bytes should be accepted")
	atUpstream, reached := srv.recorder.get("at-limit")
	assert.True(t, reached, "permitted tool call at max_request_bytes should reach the upstream")
	assert.Equal(t, atClient, atUpstream, "permitted tool call should pass through intact")

	// A well-formed tools/call padded one byte past the limit.
	status, atClient = postToolCall("oversized", maxRequestBytes+1, "hello", nil)
	assert.Equal(t, http.StatusRequestEntityTooLarge, status, "oversized tool call should be rejected")
	atUpstream, reached = srv.recorder.get("oversized")
	assert.False(t, reached, "oversized tool call must not reach the upstream, but it received %d of %d request bytes",
		atUpstream.Request, atClient.Request)
	assert.Zero(t, srv.helloCalls.Load(), "oversized forbidden tool call must not run")

	// A tools/call padded so that Envoy, buffering max_request_bytes+1
	// bytes, cuts a multi-byte character in two: the truncated body is not
	// valid UTF-8, but it is still oversized.
	call, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": "oversized-split", "method": "tools/call",
		"params": map[string]any{"name": "hello", "arguments": map[string]any{"message": strings.Repeat("é", 64)}},
	})
	require.NoError(t, err)
	split := bytes.IndexRune(call, 'é')
	body := append(bytes.Repeat([]byte(" "), maxRequestBytes-split), call...)
	require.False(t, utf8.Valid(body[:maxRequestBytes+1]), "the buffered prefix should end mid-character")
	status, atClient = srv.post(ctx, t, "oversized-split", body, srv.protocolVersion())
	assert.Equal(t, http.StatusRequestEntityTooLarge, status, "oversized tool call cut mid-character should be rejected as too large")
	atUpstream, reached = srv.recorder.get("oversized-split")
	assert.False(t, reached, "oversized tool call must not reach the upstream, but it received %d of %d request bytes",
		atUpstream.Request, atClient.Request)

	assert.LessOrEqual(t, srv.recorder.maxRequest(), maxRequestBytes,
		"no request body over max_request_bytes should reach the upstream")
}
