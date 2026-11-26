package evaluator

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"strings"

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
		return mcpReq, checkMCPHeadersWithoutRequest(ht.GetHeaders())
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
	if err := checkMCPMethodHeader(ht.GetHeaders(), msg); err != nil {
		return mcpReq, err
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
		if header, ok := ht.GetHeaders()["mcp-name"]; ok {
			name, err := decodeMCPHeaderValue(header)
			if err != nil {
				return mcpReq, fmt.Errorf("failed to decode Mcp-Name header %q: %w", header, err)
			}
			if name != toolCall.Name {
				return mcpReq, fmt.Errorf("tool name %q does not match the Mcp-Name header %q", toolCall.Name, header)
			}
		}
		mcpReq.ToolCall = &toolCall
	}

	return mcpReq, nil
}

func checkMCPMethodHeader(headers map[string]string, msg jsonrpc.Message) error {
	req, ok := msg.(*jsonrpc.Request)
	if !ok {
		return checkMCPHeadersWithoutRequest(headers)
	}
	if header, ok := headers["mcp-method"]; ok && header != req.Method {
		return fmt.Errorf("request method %q does not match the Mcp-Method header %q", req.Method, header)
	}
	return nil
}

func checkMCPHeadersWithoutRequest(headers map[string]string) error {
	for _, name := range []string{"mcp-method", "mcp-name"} {
		if _, ok := headers[name]; ok {
			return fmt.Errorf("%s header on a request that carries no JSON-RPC request", name)
		}
	}
	return nil
}

// decodeMCPHeaderValue returns the value an Mcp-Name header carries. A value
// that cannot be sent as a plain header value is sent as "=?base64?" +
// base64(value) + "?=". Only the canonical padded standard base64 encoding is
// accepted, so that no encoded form decodes differently for authorization
// than for a stricter decoder.
// see https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http#value-encoding
func decodeMCPHeaderValue(header string) (string, error) {
	encoded, ok := strings.CutPrefix(header, "=?base64?")
	if ok {
		encoded, ok = strings.CutSuffix(encoded, "?=")
	}
	if !ok {
		return header, nil
	}
	// The decoder skips CR and LF, which are not part of any base64 encoding.
	if strings.ContainsAny(encoded, "\r\n") {
		return "", errors.New("base64 value contains a line break")
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(encoded)
	return string(decoded), err
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
