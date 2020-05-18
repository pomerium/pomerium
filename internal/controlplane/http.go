// Package controlplane contains the HTTP and gRPC base servers and the xDS gRPC implementation for envoy.
package controlplane

import (
	"net/http"
	"time"

	"github.com/gorilla/handlers"
	"github.com/pomerium/pomerium/internal/frontend"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/middleware"
	"github.com/pomerium/pomerium/internal/version"
)

func (srv *Server) addHTTPMiddleware() {
	root := srv.HTTPRouter
	root.Use(log.NewHandler(log.Logger))
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
	root.Use(handlers.RecoveryHandler())
	root.Use(log.HeadersHandler(httputil.HeadersXForwarded))
	root.Use(log.RemoteAddrHandler("ip"))
	root.Use(log.UserAgentHandler("user_agent"))
	root.Use(log.RefererHandler("referer"))
	root.Use(log.RequestIDHandler("req_id", "Request-Id"))
	root.Use(middleware.Healthcheck("/ping", version.UserAgent()))
	root.HandleFunc("/healthz", httputil.HealthCheck)
	root.HandleFunc("/ping", httputil.HealthCheck)
	root.PathPrefix("/.pomerium/assets/").Handler(http.StripPrefix("/.pomerium/assets/", frontend.MustAssetHandler()))
}
