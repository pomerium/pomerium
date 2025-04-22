package mcp

import (
	"context"
	"net/http"
	"path"

	"github.com/gorilla/mux"
	"github.com/rs/cors"
	oteltrace "go.opentelemetry.io/otel/trace"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/pkg/telemetry/trace"
)

const (
	DefaultPrefix = "/.pomerium/mcp"

	authorizationEndpoint = "/authorize"
	oauthCallbackEndpoint = "/oauth/callback"
	registerEndpoint      = "/register"
	revocationEndpoint    = "/revoke"
	tokenEndpoint         = "/token"
)

type Handler struct {
	prefix string
	trace  oteltrace.TracerProvider
}

func New(
	ctx context.Context,
	prefix string,
	_ *config.Config,
) (*Handler, error) {
	tracerProvider := trace.NewTracerProvider(ctx, "MCP")
	return &Handler{
		prefix: prefix,
		trace:  tracerProvider,
	}, nil
}

// HandlerFunc returns a http.HandlerFunc that handles the mcp endpoints.
func (srv *Handler) HandlerFunc() http.HandlerFunc {
	r := mux.NewRouter()
	r.Use(cors.New(cors.Options{
		AllowedMethods: []string{http.MethodGet, http.MethodPost, http.MethodOptions},
		AllowedOrigins: []string{"*"},
		AllowedHeaders: []string{"content-type", "mcp-protocol-version"},
	}).Handler)
	r.Methods(http.MethodOptions).HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	r.Path(path.Join(srv.prefix, registerEndpoint)).Methods(http.MethodPost).HandlerFunc(srv.RegisterClient)
	r.Path(path.Join(srv.prefix, authorizationEndpoint)).Methods(http.MethodGet).HandlerFunc(srv.Authorize)
	r.Path(path.Join(srv.prefix, oauthCallbackEndpoint)).Methods(http.MethodGet).HandlerFunc(srv.OAuthCallback)
	r.Path(path.Join(srv.prefix, tokenEndpoint)).Methods(http.MethodPost).HandlerFunc(srv.Token)

	return r.ServeHTTP
}
