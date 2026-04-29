package configapi

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"github.com/ettle/strcase"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/dynamicpb"
)

// registerTools walks a protobuf FileDescriptor's services and registers each
// non-streaming RPC method as an MCP tool on the server.
func registerTools(
	s *mcp.Server,
	caller *dynamicCaller,
	fileDesc protoreflect.FileDescriptor,
	cfg *handlerConfig,
) {
	svcs := fileDesc.Services()
	for i := range svcs.Len() {
		svc := svcs.Get(i)
		methods := svc.Methods()
		for j := range methods.Len() {
			method := methods.Get(j)
			methodName := string(method.Name())
			if cfg.skip[methodName] {
				continue
			}
			if method.IsStreamingClient() || method.IsStreamingServer() {
				continue
			}
			registerMethod(s, caller, method, cfg)
		}
	}
}

func registerMethod(
	s *mcp.Server,
	caller *dynamicCaller,
	method protoreflect.MethodDescriptor,
	cfg *handlerConfig,
) {
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
				return nil, nil, fmt.Errorf("invalid input: %w", err)
			}
			inputJSON = b
		}

		if strings.HasPrefix(methodName, "Update") {
			merged, ok, err := applyUpdatePatch(ctx, caller, method, inputJSON)
			if err != nil {
				slog.Warn("mcp configapi sparse-patch merge failed; dispatching as-is",
					"tool", toolName, "error", err)
			} else if ok {
				inputJSON = merged
			}
		}

		respJSON, err := caller.call(ctx, method, inputJSON)
		if err != nil {
			slog.Error("mcp configapi tool call failed",
				"tool", toolName,
				"method", string(method.FullName()),
				"error", err)
			for _, mapErr := range cfg.errMappers {
				err = mapErr(ctx, method, err)
			}
			return nil, nil, err
		}

		respMsg := dynamicpb.NewMessage(method.Output())
		if err := protojson.Unmarshal(respJSON, respMsg); err != nil {
			return nil, nil, fmt.Errorf("invalid response JSON: %w", err)
		}

		ScrubSensitive(respMsg)

		scrubbedJSON, err := protojson.Marshal(respMsg)
		if err != nil {
			return nil, nil, fmt.Errorf("re-marshaling scrubbed response: %w", err)
		}

		var structured map[string]any
		if err := json.Unmarshal(scrubbedJSON, &structured); err != nil {
			return nil, nil, fmt.Errorf("invalid scrubbed response JSON: %w", err)
		}

		content := []mcp.Content{&mcp.TextContent{Text: string(scrubbedJSON)}}
		for _, enrich := range cfg.enrichers {
			content = append(content, enrich(ctx, method, respMsg)...)
		}

		return &mcp.CallToolResult{Content: content}, structured, nil
	})
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
