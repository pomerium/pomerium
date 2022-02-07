// Package controlplane contains the HTTP and gRPC base servers and the xDS gRPC implementation for envoy.
package controlplane

import (
	"net/http"
	"net/http/pprof"
	"time"

	"github.com/CAFxX/httpcompression"
	"github.com/gorilla/handlers"

	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/telemetry"
	"github.com/pomerium/pomerium/internal/telemetry/requestid"
)

func (srv *Server) addHTTPMiddleware() {
	compressor, err := httpcompression.DefaultAdapter()
	if err != nil {
		panic(err)
	}

	root := srv.HTTPRouter
	root.Use(compressor)
	root.Use(srv.reproxy.Middleware)
	root.Use(requestid.HTTPMiddleware())
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
	root.Use(log.RequestIDHandler("request-id"))
	root.Use(telemetry.HTTPStatsHandler(func() string {
		return srv.currentConfig.Load().Options.InstallationID
	}, srv.name))
	root.HandleFunc("/healthz", httputil.HealthCheck)
	root.HandleFunc("/ping", httputil.HealthCheck)

	// pprof
	root.Path("/debug/pprof/cmdline").HandlerFunc(pprof.Cmdline)
	root.Path("/debug/pprof/profile").HandlerFunc(pprof.Profile)
	root.Path("/debug/pprof/symbol").HandlerFunc(pprof.Symbol)
	root.Path("/debug/pprof/trace").HandlerFunc(pprof.Trace)
	root.PathPrefix("/debug/pprof/").HandlerFunc(pprof.Index)

	// metrics
	root.Handle("/metrics", srv.metricsMgr)
}
