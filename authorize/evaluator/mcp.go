package evaluator

import (
	"encoding/json"

	envoy_service_auth_v3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
)

// RequestMCP is the MCP field in the request.
type RequestMCP struct {
	Method   string              `json:"method,omitempty"`
	ToolCall *RequestMCPToolCall `json:"tool_call,omitempty"`
}

// RequestMCPToolCall represents a tool call within an MCP request.
type RequestMCPToolCall struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments"`
}

// RequestMCPFromCheckRequest populates a RequestMCP from an Envoy CheckRequest proto for MCP routes.
func RequestMCPFromCheckRequest(
	in *envoy_service_auth_v3.CheckRequest,
) (RequestMCP, bool) {
	var mcpReq RequestMCP

	body := in.GetAttributes().GetRequest().GetHttp().GetBody()
	if body == "" {
		return mcpReq, false
	}

	var jsonRPCReq struct {
		Method string          `json:"method"`
		Params json.RawMessage `json:"params,omitempty"`
	}

	if err := json.Unmarshal([]byte(body), &jsonRPCReq); err != nil {
		return mcpReq, false
	}

	mcpReq.Method = jsonRPCReq.Method

	if jsonRPCReq.Method == "tools/call" {
		var toolCall RequestMCPToolCall
		err := json.Unmarshal(jsonRPCReq.Params, &toolCall)
		if err != nil {
			return mcpReq, false
		}
		mcpReq.ToolCall = &toolCall
	}

	return mcpReq, true
}
