package authorize

import (
	"net/http"
	"testing"

	envoy_service_auth_v3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/stretchr/testify/assert"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/config/envoyconfig"
)

// TestMCPRuntimeFlagOffDoesNotSkipToolCallInspection verifies that turning the
// mcp runtime flag off does not fail open for MCP server routes:
// Envoy still buffers and forwards request bodies for them (the route config
// is keyed on the policy, not the flag) and the route still proxies to the MCP
// server for cookie or IdP-token sessions, so the body must still be
// inspected, or mcp_tool deny rules in the route's policy would never match
// and a forbidden tool call would be forwarded.
//
// The invariant: with the flag off, a tool call on an MCP server route is
// either rejected or evaluated as that tool call.
func TestMCPRuntimeFlagOffDoesNotSkipToolCallInspection(t *testing.T) {
	t.Parallel()

	a := &Authorize{}
	a.currentConfig.Store(config.New(&config.Options{
		RuntimeFlags: config.RuntimeFlags{config.RuntimeFlagMCP: false},
		Policies: []config.Policy{{
			ID:   "mcp",
			From: "https://mcp.example.com",
			MCP:  &config.MCP{Server: &config.MCPServer{}},
		}},
	}))
	a.state.Store(new(authorizeState))

	req, err := a.getEvaluatorRequestFromCheckRequest(t.Context(),
		&envoy_service_auth_v3.CheckRequest{
			Attributes: &envoy_service_auth_v3.AttributeContext{
				ContextExtensions: envoyconfig.MakeExtAuthzContextExtensions(false, "mcp", 0),
				Request: &envoy_service_auth_v3.AttributeContext_Request{
					Http: &envoy_service_auth_v3.AttributeContext_HttpRequest{
						Method: http.MethodPost,
						Headers: map[string]string{
							"content-type":         "application/json",
							"mcp-protocol-version": "2025-11-25",
						},
						Host: "mcp.example.com",
						Body: `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"hello"}}`,
					},
				},
			},
		},
	)
	if err != nil {
		return // rejected: the upstream never sees the body
	}
	if assert.NotNil(t, req.MCP.ToolCall, "a forwarded body naming tool hello was evaluated as %+v", req.MCP) {
		assert.Equal(t, "hello", req.MCP.ToolCall.Name)
	}
}
