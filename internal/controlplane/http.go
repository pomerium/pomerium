// Package controlplane contains the HTTP and gRPC base servers and the xDS gRPC implementation for envoy.
package controlplane

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/CAFxX/httpcompression"
	"github.com/gorilla/mux"
	"github.com/rs/zerolog"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/handlers"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/mcp"
	"github.com/pomerium/pomerium/internal/middleware"
	"github.com/pomerium/pomerium/internal/telemetry"
	"github.com/pomerium/pomerium/pkg/endpoints"
	hpke_handlers "github.com/pomerium/pomerium/pkg/hpke/handlers"
	"github.com/pomerium/pomerium/pkg/telemetry/requestid"
	"github.com/pomerium/pomerium/pkg/telemetry/trace"
)

func (srv *Server) addHTTPMiddleware(ctx context.Context, root *mux.Router, _ *config.Config) {
	logger := log.Ctx(ctx)
	compressor, err := httpcompression.DefaultAdapter()
	if err != nil {
		panic(err)
	}

	root.Use(compressor)
	root.Use(srv.reproxy.Middleware)
	root.Use(requestid.HTTPMiddleware())
	root.Use(log.NewHandler(func() *zerolog.Logger { return logger }))
	root.Use(log.AccessHandler(func(r *http.Request, status, size int, duration time.Duration) {
		log.FromRequest(r).Debug().
			Dur("duration", duration).
			Int("size", size).
			Int("status", status).
			Str("method", r.Method).
			Str("host", r.Host).
			Str("path", r.URL.String()).
			Msg("http-request")
	}))
	root.Use(middleware.Recovery)
	root.Use(log.RemoteAddrHandler("ip"))
	root.Use(log.UserAgentHandler("user_agent"))
	root.Use(log.RefererHandler("referer"))
	root.Use(log.RequestIDHandler("request-id"))
	root.Use(telemetry.HTTPStatsHandler(func() string {
		return srv.currentConfig.Load().Options.InstallationID
	}, srv.name))
}

func (srv *Server) mountCommonEndpoints(root *mux.Router, cfg *config.Config) error {
	authenticateURL, err := cfg.Options.GetAuthenticateURL()
	if err != nil {
		return fmt.Errorf("invalid authenticate URL: %w", err)
	}

	signingKey, err := cfg.Options.GetSigningKey()
	if err != nil {
		return fmt.Errorf("invalid signing key: %w", err)
	}

	hpkePrivateKey, err := cfg.Options.GetHPKEPrivateKey()
	if err != nil {
		return fmt.Errorf("invalid hpke private key: %w", err)
	}
	hpkePublicKey := hpkePrivateKey.PublicKey()

	root.HandleFunc(endpoints.PathHealthz, handlers.HealthCheck)
	root.HandleFunc(endpoints.PathPing, handlers.HealthCheck)

	traceHandler := trace.NewHTTPMiddleware(otelhttp.WithTracerProvider(srv.tracerProvider))
	root.Handle(endpoints.PathWellKnownPomerium, traceHandler(handlers.WellKnownPomerium(authenticateURL)))
	root.Handle(endpoints.PathWellKnownPomerium+"/", traceHandler(handlers.WellKnownPomerium(authenticateURL)))
	root.Path(endpoints.PathJWKS).Methods(http.MethodGet).Handler(traceHandler(handlers.JWKSHandler(signingKey)))
	root.Path(endpoints.PathHPKEPublicKey).Methods(http.MethodGet).Handler(traceHandler(hpke_handlers.HPKEPublicKeyHandler(hpkePublicKey)))

	if cfg.Options.IsRuntimeFlagSet(config.RuntimeFlagMCP) {
		root.Path(mcp.WellKnownAuthorizationServerEndpoint).
			Methods(http.MethodGet, http.MethodOptions).
			Handler(mcp.AuthorizationServerMetadataHandler(mcp.DefaultPrefix))
		root.PathPrefix(mcp.WellKnownProtectedResourceEndpoint).
			Methods(http.MethodGet, http.MethodOptions).
			Handler(mcp.ProtectedResourceMetadataHandler(mcp.DefaultPrefix))

	}

	return nil
}
