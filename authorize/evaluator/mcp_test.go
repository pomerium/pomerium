package evaluator

import (
	"net/http"
	"testing"

	envoy_service_auth_v3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/stretchr/testify/assert"
)

func TestRequestMCPFromCheckRequest(t *testing.T) {
	t.Parallel()

	const (
		toolsList = `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`
		toolCall  = `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo"}}`
	)

	for _, tc := range []struct {
		name    string
		method  string
		body    string
		wantErr bool
	}{
		{"GET", http.MethodGet, "", false},
		{"request", http.MethodPost, toolsList, false},
		{"response", http.MethodPost, `{"jsonrpc":"2.0","id":1,"result":{}}`, false},
		{"notification", http.MethodPost, `{"jsonrpc":"2.0","method":"notifications/initialized"}`, false},
		{"tool call", http.MethodPost, toolCall, false},
		{"trailing data", http.MethodPost, toolCall + `x`, true},
		{"second message", http.MethodPost, toolCall + toolCall, true},
		{"batch", http.MethodPost, `[` + toolCall + `]`, true},
		{"null method", http.MethodPost, `{"jsonrpc":"2.0","id":1,"method":null}`, true},
		{"null tool name", http.MethodPost, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":null}}`, true},
		{"tool call without params", http.MethodPost, `{"jsonrpc":"2.0","id":1,"method":"tools/call"}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := RequestMCPFromCheckRequest(&envoy_service_auth_v3.CheckRequest{
				Attributes: &envoy_service_auth_v3.AttributeContext{
					Request: &envoy_service_auth_v3.AttributeContext_Request{
						Http: &envoy_service_auth_v3.AttributeContext_HttpRequest{
							Method: tc.method,
							Headers: map[string]string{
								"content-type":         "application/json",
								"mcp-protocol-version": "2025-11-25",
							},
							Body: tc.body,
						},
					},
				},
			})
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestRequestMCPFromCheckRequestMemberNamesAreCaseSensitive(t *testing.T) {
	t.Parallel()

	for _, body := range []string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"hello","Name":"echo"}}`,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"NAME":"echo","name":"hello","nAmE":"echo"}}`,
		`{"jsonrpc":"2.0","id":1,"Method":"tools/list","method":"tools/call","METHOD":"tools/list","params":{"name":"hello"}}`,
	} {
		mcpReq, err := RequestMCPFromCheckRequest(&envoy_service_auth_v3.CheckRequest{
			Attributes: &envoy_service_auth_v3.AttributeContext{
				Request: &envoy_service_auth_v3.AttributeContext_Request{
					Http: &envoy_service_auth_v3.AttributeContext_HttpRequest{
						Method: http.MethodPost,
						Headers: map[string]string{
							"content-type":         "application/json",
							"mcp-protocol-version": "2025-11-25",
						},
						Body: body,
					},
				},
			},
		})
		if assert.NoError(t, err, body) && assert.NotNil(t, mcpReq.ToolCall, body) {
			assert.Equal(t, "tools/call", mcpReq.Method, body)
			assert.Equal(t, "hello", mcpReq.ToolCall.Name, body)
		}
	}

	t.Run("arguments", func(t *testing.T) {
		t.Parallel()

		mcpReq, err := RequestMCPFromCheckRequest(&envoy_service_auth_v3.CheckRequest{
			Attributes: &envoy_service_auth_v3.AttributeContext{
				Request: &envoy_service_auth_v3.AttributeContext_Request{
					Http: &envoy_service_auth_v3.AttributeContext_HttpRequest{
						Method: http.MethodPost,
						Headers: map[string]string{
							"content-type":         "application/json",
							"mcp-protocol-version": "2025-11-25",
						},
						Body: `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"message":"hi"},"Arguments":{"message":"bye"}}}`,
					},
				},
			},
		})
		if assert.NoError(t, err) && assert.NotNil(t, mcpReq.ToolCall) {
			assert.Equal(t, map[string]any{"message": "hi"}, mcpReq.ToolCall.Arguments)
		}
	})
}
