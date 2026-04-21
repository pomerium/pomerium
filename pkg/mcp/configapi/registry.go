package configapi

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"github.com/ettle/strcase"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// skipMethods lists methods that should not be exposed as MCP tools.
var skipMethods = map[string]bool{
	"GetServerInfo": true,
}

// registerTools walks a protobuf FileDescriptor's services and registers each
// non-streaming RPC method as an MCP tool on the server.
func registerTools(
	s *mcp.Server,
	caller *dynamicCaller,
	fileDesc protoreflect.FileDescriptor,
) {
	svcs := fileDesc.Services()
	for i := range svcs.Len() {
		svc := svcs.Get(i)
		methods := svc.Methods()
		for j := range methods.Len() {
			method := methods.Get(j)
			methodName := string(method.Name())
			if skipMethods[methodName] {
				continue
			}
			if method.IsStreamingClient() || method.IsStreamingServer() {
				continue
			}
			registerMethod(s, caller, method)
		}
	}
}

func registerMethod(s *mcp.Server, caller *dynamicCaller, method protoreflect.MethodDescriptor) {
	methodName := string(method.Name())
	toolName := strcase.ToSnake(methodName)

	tool := &mcp.Tool{
		Name:         toolName,
		Title:        strcase.ToCase(methodName, strcase.TitleCase, ' '),
		Description:  buildDescription(method),
		InputSchema:  messageToJSONSchema(method.Input()),
		OutputSchema: messageToJSONSchema(method.Output()),
		Annotations:  annotationsForMethod(methodName),
	}

	mcp.AddTool(s, tool, func(
		ctx context.Context,
		_ *mcp.CallToolRequest,
		args map[string]any,
	) (*mcp.CallToolResult, map[string]any, error) {
		var inputJSON json.RawMessage
		if args != nil {
			b, err := json.Marshal(args)
			if err != nil {
				return errorResult("invalid input: " + err.Error()), nil, nil
			}
			inputJSON = b
		}

		respJSON, err := caller.call(ctx, method, inputJSON)
		if err != nil {
			slog.Error("mcp configapi tool call failed",
				"tool", toolName,
				"method", string(method.FullName()),
				"error", err)
			return errorResult(err.Error()), nil, nil
		}

		var structured map[string]any
		if err := json.Unmarshal(respJSON, &structured); err != nil {
			return errorResult("invalid response JSON: " + err.Error()), nil, nil
		}

		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: string(respJSON)}},
		}, structured, nil
	})
}

func errorResult(msg string) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		IsError: true,
	}
}

func buildDescription(method protoreflect.MethodDescriptor) string {
	methodName := string(method.Name())

	var action, resource string
	for _, prefix := range []string{"Create", "Get", "List", "Update", "Delete"} {
		if strings.HasPrefix(methodName, prefix) {
			action = prefix
			resource = methodName[len(prefix):]
			break
		}
	}

	if action != "" && resource != "" {
		readable := camelToLowerWords(resource)
		if action == "List" {
			return fmt.Sprintf("List %s.", readable)
		}
		return fmt.Sprintf("%s a %s.", action, readable)
	}

	return camelToLowerWords(methodName) + "."
}

// camelToLowerWords returns the CamelCase input as space-separated lowercase
// words, e.g. "CreateRoute" -> "create route". strcase has no direct helper
// for this casing, so we derive it from ToSnake.
func camelToLowerWords(s string) string {
	return strings.ReplaceAll(strcase.ToSnake(s), "_", " ")
}
