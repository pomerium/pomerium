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

// MetaContributor returns structured metadata to merge under the _meta
// key of MCP tool results. response is the (already sensitive-scrubbed)
// protobuf response; redactedFields is the JSON-path list of sensitive
// fields that were populated before scrubbing. Returning nil contributes
// nothing. Multiple contributors compose; later wins on key collision.
//
// Use this to surface product-specific entries like links.canonical (the
// admin-UI URL for the entity) or category-specific status hints. The
// schema for _meta is fixed and documented in outputSchema.
type MetaContributor func(
	ctx context.Context,
	method protoreflect.MethodDescriptor,
	response proto.Message,
	redactedFields []string,
) map[string]any

// ErrorMapper transforms an error returned by an MCP tool call before it is
// surfaced to the client. Use it to redact internal details or to replace
// well-known error categories with product-specific user-facing messages
// (e.g. quota exhaustion → "visit your billing console"). The supplied
// error is the raw error from the in-process Connect call: typically a
// typed *connect.Error so consumers can match via errors.As. Returning the
// input unchanged leaves the message as-is.
type ErrorMapper func(ctx context.Context, method protoreflect.MethodDescriptor, err error) error

// ServerMutator is invoked once with the underlying *mcp.Server after
// configapi has registered the auto-generated config-service tools, but
// before the HTTP handler is sealed. Use it to register additional tools,
// resources, or prompts that are not derived from the config-service
// descriptor (e.g. product-specific discovery tools that callers need but
// that should not live in the upstream proto). The callback must not retain
// the *mcp.Server beyond its invocation.
type ServerMutator func(*mcp.Server)

// InputSchemaContributor lets callers post-process the auto-generated input
// JSON Schema for each proto-derived MCP tool. It runs after the schema is
// built from the method's input descriptor and before the tool is registered.
// Returning a different map replaces the generated schema (in-place mutation
// is also fine — the same map is returned by convention).
//
// Use this to surface product-specific top-level fields the proto request
// type does not carry (scope IDs, tenant identifiers, etc.). The values are
// available to a registered PreCall on each invocation; this option does not
// route values anywhere on its own.
//
// Only proto-derived tools are subject to this contributor. Tools added via
// WithServerMutator manage their own schemas.
type InputSchemaContributor func(method protoreflect.MethodDescriptor, schema map[string]any) map[string]any

// PreCall is invoked at the top of every proto-derived tool dispatch, before
// the in-process Connect call runs. It may inspect or mutate the args map
// (e.g., remove fields the auto-tool input schema accepts but the Connect
// request body should not carry), set Connect request headers via setHeader
// (which the downstream handler may consult), and short-circuit the call by
// returning a non-nil error. Errors flow through ErrorMappers, so they reach
// the MCP client as MCP errors.
//
// PreCalls run in registration order. Only proto-derived tools invoke them;
// tools added via WithServerMutator are responsible for their own input
// validation and dispatch.
type PreCall func(
	ctx context.Context,
	method protoreflect.MethodDescriptor,
	args map[string]any,
	setHeader func(name, value string),
) error

type handlerConfig struct {
	modifiers               []RequestModifier
	skip                    map[string]bool
	metaContributors        []MetaContributor
	errMappers              []ErrorMapper
	serverMutators          []ServerMutator
	inputSchemaContributors []InputSchemaContributor
	preCalls                []PreCall
}

// RequestModifier mutates an in-memory Connect request before it is
// dispatched. Typical use: attach an Authorization header for the
// downstream ConfigService implementation. Returning a non-nil error
// aborts the dispatch — the tool call surfaces the error to the MCP
// client via the configured ErrorMappers, so a missing shared key (or
// any other config problem inside the modifier) reaches the operator
// as a structured tool failure rather than a generic unauthenticated
// response from the downstream handler.
type RequestModifier func(*http.Request) error

// WithRequestModifier registers a modifier invoked on every in-memory
// Connect request produced by a tool call, before the request is
// dispatched against connectHandler. See RequestModifier.
func WithRequestModifier(fn RequestModifier) Option {
	return func(c *handlerConfig) {
		if fn != nil {
			c.modifiers = append(c.modifiers, fn)
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

// WithMetaContributor registers a function that contributes structured
// metadata to the _meta object on every successful tool result (e.g.
// links.canonical pointing at the admin UI). Multiple contributors compose
// in registration order; later writes win on key collision.
func WithMetaContributor(fn MetaContributor) Option {
	return func(c *handlerConfig) {
		if fn != nil {
			c.metaContributors = append(c.metaContributors, fn)
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

// WithServerMutator registers a callback that runs once with the underlying
// *mcp.Server after auto-generated tool registration. Multiple mutators
// compose in registration order. Use to attach product-specific tools (or
// future resources/prompts) without leaking those concepts into the upstream
// configapi package.
func WithServerMutator(fn ServerMutator) Option {
	return func(c *handlerConfig) {
		if fn != nil {
			c.serverMutators = append(c.serverMutators, fn)
		}
	}
}

// WithInputSchemaContributor registers a function that post-processes the
// auto-generated input schema for every proto-derived tool. Multiple
// contributors compose in registration order; each receives the schema
// produced by the previous one.
func WithInputSchemaContributor(fn InputSchemaContributor) Option {
	return func(c *handlerConfig) {
		if fn != nil {
			c.inputSchemaContributors = append(c.inputSchemaContributors, fn)
		}
	}
}

// WithPreCall registers a function invoked before each proto-derived tool
// dispatch. PreCalls run in registration order; an error from any PreCall
// short-circuits the dispatch and flows through ErrorMappers.
func WithPreCall(fn PreCall) Option {
	return func(c *handlerConfig) {
		if fn != nil {
			c.preCalls = append(c.preCalls, fn)
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
// downstream handler must be supplied via WithRequestModifier; NewHandler
// itself neither adds nor enforces authentication.
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

	// Built-in PreCall: clamp List* limit so a single tool call cannot pull
	// the entire dataset into memory. Prepended so it runs before any
	// caller-registered PreCall, and so user-supplied PreCalls observe the
	// already-clamped value.
	cfg.preCalls = append([]PreCall{listLimitClamp}, cfg.preCalls...)

	caller := newDynamicCaller(connectHandler, cfg.modifiers)

	server := mcp.NewServer(&mcp.Implementation{
		Name:    "pomerium-config",
		Version: "1.0.0",
	}, nil)

	registerTools(server, caller, configpb.File_config_proto, cfg)

	for _, mutate := range cfg.serverMutators {
		mutate(server)
	}

	return mcp.NewStreamableHTTPHandler(
		func(_ *http.Request) *mcp.Server { return server },
		&mcp.StreamableHTTPOptions{
			Stateless: true,
			Logger:    slog.Default(),
			// The SDK's DNS-rebinding guard is for standalone MCP servers
			// reachable directly from a browser. configapi is only embedded
			// in product binaries (zero, console) that sit behind the
			// Pomerium proxy, which already enforces Origin/CSRF and auth on
			// every request. Leaving the guard on rejects forwarded
			// requests whose upstream host happens to resolve to loopback
			// (common in dev: *.localhost.pomerium.io).
			DisableLocalhostProtection: true,
		},
	)
}
