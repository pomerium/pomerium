package configapi

import (
	"log/slog"
	"net/http"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	configpb "github.com/pomerium/pomerium/pkg/grpc/config"
)

// Option customizes a handler returned by NewHandler.
type Option func(*handlerConfig)

type handlerConfig struct {
	stamps []func(*http.Request)
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
func NewHandler(connectHandler http.Handler, opts ...Option) http.Handler {
	cfg := &handlerConfig{}
	for _, o := range opts {
		o(cfg)
	}

	caller := newDynamicCaller(connectHandler, cfg.stamps)

	server := mcp.NewServer(&mcp.Implementation{
		Name:    "pomerium-config",
		Version: "1.0.0",
	}, nil)

	registerTools(server, caller, configpb.File_config_proto)

	return mcp.NewStreamableHTTPHandler(
		func(_ *http.Request) *mcp.Server { return server },
		&mcp.StreamableHTTPOptions{
			Stateless: true,
			Logger:    slog.Default(),
		},
	)
}
