// Package controlplane contains the HTTP and gRPC base servers and the xDS gRPC implementation for envoy.
package controlplane

import (
	"net/http"
	"net/url"
	"time"

	"github.com/CAFxX/httpcompression"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"

	"github.com/pomerium/csrf"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/telemetry"
	"github.com/pomerium/pomerium/internal/telemetry/requestid"
)

func (srv *Server) addHTTPMiddleware(root *mux.Router, cfg *config.Config) {
	compressor, err := httpcompression.DefaultAdapter()
	if err != nil {
		panic(err)
	}

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
	root.Handle("/.well-known/pomerium", httputil.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		return wellKnownPomerium(w, r, cfg)
	}))
	root.Handle("/.well-known/pomerium/", httputil.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		return wellKnownPomerium(w, r, cfg)
	}))
}

func wellKnownPomerium(w http.ResponseWriter, r *http.Request, cfg *config.Config) error {
	authenticateURL, err := cfg.Options.GetAuthenticateURL()
	if err != nil {
		return err
	}

	wellKnownURLs := struct {
		OAuth2Callback        string `json:"authentication_callback_endpoint"` // RFC6749
		JSONWebKeySetURL      string `json:"jwks_uri"`                         // RFC7517
		FrontchannelLogoutURI string `json:"frontchannel_logout_uri"`          // https://openid.net/specs/openid-connect-frontchannel-1_0.html
	}{
		authenticateURL.ResolveReference(&url.URL{Path: "/oauth2/callback"}).String(),
		authenticateURL.ResolveReference(&url.URL{Path: "/.well-known/pomerium/jwks.json"}).String(),
		authenticateURL.ResolveReference(&url.URL{Path: "/.pomerium/sign_out"}).String(),
	}
	w.Header().Set("X-CSRF-Token", csrf.Token(r))
	httputil.RenderJSON(w, http.StatusOK, wellKnownURLs)
	return nil
}
