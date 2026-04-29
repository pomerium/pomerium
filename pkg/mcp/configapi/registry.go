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
	"google.golang.org/protobuf/proto"
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
		OutputSchema: outputSchema(method.Output()),
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

		// Always build the response message from the descriptor we received
		// from configpb.File_config_proto. Going through
		// protoregistry.GlobalTypes can return a shadow Go type from a
		// sibling module that vendors the same .proto file (e.g. when
		// -X protoregistry.conflictPolicy=ignore lets a duplicate
		// registration silently coexist) — its FieldOptions would lack our
		// custom (sensitive) extension and reflection-based scrub would
		// no-op. dynamicpb is unambiguous: the descriptor we hold is the
		// only thing it reflects.
		respMsg := dynamicpb.NewMessage(method.Output())
		if err := protojson.Unmarshal(respJSON, respMsg); err != nil {
			return nil, nil, fmt.Errorf("invalid response JSON: %w", err)
		}

		// Snapshot which sensitive fields are populated *before* scrubbing,
		// so the response can advertise what's hidden.
		redacted := SensitiveFieldsSet(respMsg)

		ScrubSensitive(respMsg)

		scrubbedJSON, err := protojson.Marshal(respMsg)
		if err != nil {
			return nil, nil, fmt.Errorf("re-marshaling scrubbed response: %w", err)
		}

		var structured map[string]any
		if err := json.Unmarshal(scrubbedJSON, &structured); err != nil {
			return nil, nil, fmt.Errorf("invalid scrubbed response JSON: %w", err)
		}

		if meta := buildMeta(ctx, method, respMsg, redacted, cfg.metaContributors); len(meta) > 0 {
			structured["_meta"] = meta
		}

		// Let the SDK auto-populate Content from structured (so the JSON the
		// LLM sees in text content always matches the validated structured
		// payload, including _meta).
		return nil, structured, nil
	})
}

// buildMeta assembles the _meta object: scrubbedFields (when any were
// populated before scrubbing) plus whatever each MetaContributor returns.
// Later contributors overwrite earlier on key collision.
func buildMeta(
	ctx context.Context,
	method protoreflect.MethodDescriptor,
	respMsg proto.Message,
	redacted []string,
	contributors []MetaContributor,
) map[string]any {
	meta := map[string]any{}
	if len(redacted) > 0 {
		meta["scrubbedFields"] = redacted
	}
	for _, contribute := range contributors {
		for k, v := range contribute(ctx, method, respMsg, redacted) {
			meta[k] = v
		}
	}
	return meta
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
