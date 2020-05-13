package config

import (
	"net/http"
	"sync"

	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/log"
)

// RedirectAndAutocertServer is an HTTP server which handles redirecting to HTTPS and autocerts.
var RedirectAndAutocertServer = newRedirectAndAutoCertServer()

type redirectAndAutoCertServer struct {
	mu  sync.Mutex
	srv *http.Server
}

func newRedirectAndAutoCertServer() *redirectAndAutoCertServer {
	return &redirectAndAutoCertServer{}
}

func (srv *redirectAndAutoCertServer) update(options *Options) {
	srv.mu.Lock()
	defer srv.mu.Unlock()

	if srv.srv != nil {
		// nothing to do if the address hasn't changed
		if srv.srv.Addr == options.HTTPRedirectAddr {
			return
		}
		// close immediately, don't care about the error
		_ = srv.srv.Close()
		srv.srv = nil
	}

	if options.HTTPRedirectAddr == "" {
		return
	}

	redirect := httputil.RedirectHandler()

	hsrv := &http.Server{
		Addr: options.HTTPRedirectAddr,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if AutocertManager.HandleHTTPChallenge(w, r) {
				return
			}
			redirect.ServeHTTP(w, r)
		}),
	}
	go func() {
		log.Info().Str("addr", hsrv.Addr).Msg("starting http redirect server")
		err := hsrv.ListenAndServe()
		if err != nil {
			log.Error().Err(err).Msg("failed to run http redirect server")
		}
	}()
	srv.srv = hsrv
}
