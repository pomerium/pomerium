package evaluator

import (
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net/http"

	envoy_service_auth_v3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
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

// RequestMCPFromCheckRequest populates a RequestMCP from an Envoy CheckRequest
// proto for MCP routes. An error means a POST is not one that authorization
// can be evaluated against, and must be rejected: its body is not a single
// well-formed JSON-RPC message.
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

	if !json.Valid([]byte(body)) {
		return mcpReq, errors.New("MCP request body is not valid JSON")
	}

	msg, err := jsonrpc.DecodeMessage([]byte(body))
	if err != nil {
		return mcpReq, fmt.Errorf("failed to parse MCP request: %w", err)
	}

	jsonRPCReq, isRequest := msg.(*jsonrpc.Request)
	if !isRequest {
		// A client's response to a server request carries nothing to authorize
		// beyond the route itself.
		return mcpReq, nil
	}
	if jsonRPCReq.Method == "" {
		return mcpReq, errors.New("MCP request method is empty")
	}

	mcpReq.ID = jsonRPCReq.ID
	mcpReq.Method = jsonRPCReq.Method

	if jsonRPCReq.Method == "tools/call" {
		var toolCall RequestMCPToolCall
		if err := unmarshalMembers(jsonRPCReq.Params, map[string]any{
			"name":      &toolCall.Name,
			"arguments": &toolCall.Arguments,
		}); err != nil {
			return mcpReq, fmt.Errorf("failed to unmarshal MCP tool call parameters: %w", err)
		}
		if toolCall.Name == "" {
			return mcpReq, errors.New("MCP tool call name is empty")
		}
		mcpReq.ToolCall = &toolCall
	}

	return mcpReq, nil
}

// unmarshalMembers unmarshals the members of a JSON object into the values
// that fields points to, by exact member name. JSON-RPC member names are
// case-sensitive, so a member must not be decoded into a struct field, which
// encoding/json matches case-insensitively: authorization would then see a
// different value than an MCP server reading the same message.
func unmarshalMembers(data json.RawMessage, fields map[string]any) error {
	var members map[string]json.RawMessage
	if err := json.Unmarshal(data, &members); err != nil {
		return err
	}
	for name, v := range fields {
		if member, ok := members[name]; ok {
			if err := json.Unmarshal(member, v); err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
		}
	}
	return nil
}
