package evaluator

import (
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net/http"

	envoy_service_auth_v3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"

	"github.com/pomerium/pomerium/internal/jsonrpc"
)

// RequestMCP is the MCP field in the request.
type RequestMCP struct {
	ID       jsonrpc.ID          `json:"id"`
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
) (RequestMCP, error) {
	var mcpReq RequestMCP

	ht := in.GetAttributes().GetRequest().GetHttp()
	if ht.Method != http.MethodPost {
		return mcpReq, nil
	}

	body := ht.GetBody()
	if body == "" {
		return mcpReq, errors.New("MCP request body is empty")
	}

	contentType := ht.GetHeaders()["content-type"]
	mimeType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return mcpReq, fmt.Errorf("failed to parse content-type %q: %w", contentType, err)
	}
	if mimeType != "application/json" {
		return mcpReq, fmt.Errorf("unsupported content-type %q, expected application/json", mimeType)
	}

	jsonRPCReq, err := jsonrpc.ParseRequest([]byte(body))
	if err != nil {
		return mcpReq, fmt.Errorf("failed to parse MCP request: %w", err)
	}

	mcpReq.ID = jsonRPCReq.ID
	mcpReq.Method = jsonRPCReq.Method

	if jsonRPCReq.Method == "tools/call" {
		var toolCall RequestMCPToolCall
		err := json.Unmarshal(jsonRPCReq.Params, &toolCall)
		if err != nil {
			return mcpReq, fmt.Errorf("failed to unmarshal MCP tool call parameters: %w", err)
		}
		mcpReq.ToolCall = &toolCall
	}

	return mcpReq, nil
}
