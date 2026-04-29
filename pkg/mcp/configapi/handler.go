package configapi

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	configpb "github.com/pomerium/pomerium/pkg/grpc/config"
)

// Option customizes a handler returned by NewHandler.
type Option func(*handlerConfig)

// ResponseEnricher returns extra MCP content blocks to append to a tool
// result. response is the (already sensitive-scrubbed) protobuf response.
// redactedFields lists the JSON-name paths of sensitive fields that were
// populated on the response before scrubbing — useful for telling the
// caller "this entity has secrets configured that are not exposed here".
// Returning nil emits no extra blocks. Implementations should be cheap and
// must not retain the response.
type ResponseEnricher func(
	ctx context.Context,
	method protoreflect.MethodDescriptor,
	response proto.Message,
	redactedFields []string,
) []mcp.Content

// ErrorMapper transforms an error returned by an MCP tool call before it is
// surfaced to the client. Use it to redact internal details or to replace
// well-known error categories with product-specific user-facing messages
// (e.g. quota exhaustion → "visit your billing console"). The supplied
// error is the raw error from the in-process Connect call: typically a
// typed *connect.Error so consumers can match via errors.As. Returning the
// input unchanged leaves the message as-is.
type ErrorMapper func(ctx context.Context, method protoreflect.MethodDescriptor, err error) error

type handlerConfig struct {
	stamps     []func(*http.Request)
	skip       map[string]bool
	enrichers  []ResponseEnricher
	errMappers []ErrorMapper
}

// WithRequestStamp registers a function that is invoked on every in-memory
// Connect request produced by a tool call, before the request is dispatched
// against connectHandler. Typical use: attach an Authorization header for the
// downstream ConfigService implementation.
func WithRequestStamp(fn func(*http.Request)) Option {
	return func(c *handlerConfig) {
		if fn != nil {
			c.stamps = append(c.stamps, fn)
		}
	}
}

// WithSkippedMethods omits the named ConfigService RPC methods from the
// generated MCP tool set. Use to keep dangerous or all-secret operations
// (e.g. CreateKeyPair) out of MCP entirely. Method names are the proto RPC
// names like "CreateKeyPair", not the snake_case tool names.
func WithSkippedMethods(methods ...string) Option {
	return func(c *handlerConfig) {
		if c.skip == nil {
			c.skip = map[string]bool{}
		}
		for _, m := range methods {
			c.skip[m] = true
		}
	}
}

// WithResponseEnricher registers a function that, after each tool call,
// returns extra MCP content blocks to append to the result (e.g. canonical
// UI URLs). Multiple enrichers can be registered; their outputs are appended
// in registration order.
func WithResponseEnricher(fn ResponseEnricher) Option {
	return func(c *handlerConfig) {
		if fn != nil {
			c.enrichers = append(c.enrichers, fn)
		}
	}
}

// WithErrorMapper registers a function that may rewrite errors returned by
// tool calls before they reach the MCP client. Mappers run in registration
// order; each receives the (possibly already-mapped) error from the
// previous one. Use to scrub internal details and to redirect users to
// product-specific recovery flows on well-known error categories.
func WithErrorMapper(fn ErrorMapper) Option {
	return func(c *handlerConfig) {
		if fn != nil {
			c.errMappers = append(c.errMappers, fn)
		}
	}
}

// NewHandler returns an MCP streamable HTTP handler that exposes every RPC
// method of pomerium.config.ConfigService as an MCP tool. connectHandler must
// route paths of the form /pomerium.config.ConfigService/<Method> using the
// Connect unary JSON protocol — typically a handler obtained from
// configconnect.NewConfigServiceHandler or any http.ServeMux that has it
// registered.
//
// Tool calls are dispatched in-process; no network. Any auth required by the
// downstream handler must be supplied via WithRequestStamp; NewHandler itself
// neither adds nor enforces authentication.
//
// Sensitive fields (those marked with the (pomerium.config.sensitive) field
// option) are stripped from generated tool schemas, scrubbed from response
// payloads before they reach the MCP client, and on Update* tools are
// preserved from the existing record rather than accepted from the request.
func NewHandler(connectHandler http.Handler, opts ...Option) http.Handler {
	cfg := &handlerConfig{}
	for _, o := range opts {
		o(cfg)
	}
	if cfg.skip == nil {
		cfg.skip = map[string]bool{}
	}
	// Built-in skip: GetServerInfo is metadata, not user-facing.
	cfg.skip["GetServerInfo"] = true

	caller := newDynamicCaller(connectHandler, cfg.stamps)

	server := mcp.NewServer(&mcp.Implementation{
		Name:    "pomerium-config",
		Version: "1.0.0",
	}, nil)

	registerTools(server, caller, configpb.File_config_proto, cfg)

	return mcp.NewStreamableHTTPHandler(
		func(_ *http.Request) *mcp.Server { return server },
		&mcp.StreamableHTTPOptions{
			Stateless: true,
			Logger:    slog.Default(),
		},
	)
}
