package httputil // import "github.com/pomerium/pomerium/internal/httputil"

import (
	"context"
	"fmt"
	stdlog "log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/urlutil"
)

// NewHTTPServer starts a http server given a set of options and a handler.
//
// It is the caller's responsibility to Close() or Shutdown() the returned
// server.
func NewHTTPServer(opt *ServerOptions, h http.Handler) *http.Server {
	if opt == nil {
		opt = defaultHTTPServerOptions
	} else {
		opt.applyHTTPDefaults()
	}
	sublogger := log.With().Str("addr", opt.Addr).Logger()
	srv := http.Server{
		Addr:              opt.Addr,
		ReadHeaderTimeout: opt.ReadHeaderTimeout,
		ReadTimeout:       opt.ReadTimeout,
		WriteTimeout:      opt.WriteTimeout,
		IdleTimeout:       opt.IdleTimeout,
		Handler:           h,
		ErrorLog:          stdlog.New(&log.StdLogWrapper{Logger: &sublogger}, "", 0),
	}

	go func() {
		if err := srv.ListenAndServe(); err != http.ErrServerClosed {
			log.Error().Str("addr", opt.Addr).Err(err).Msg("internal/httputil: unexpected shutdown")
		}
	}()
	return &srv
}

func RedirectHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Connection", "close")
		url := fmt.Sprintf("https://%s%s", urlutil.StripPort(r.Host), r.URL.String())
		http.Redirect(w, r, url, http.StatusMovedPermanently)
	})
}

// Shutdown attempts to shut down the server when a os interrupt or sigterm
// signal are received without interrupting any
// active connections. Shutdown works by first closing all open
// listeners, then closing all idle connections, and then waiting
// indefinitely for connections to return to idle and then shut down.
// If the provided context expires before the shutdown is complete,
// Shutdown returns the context's error, otherwise it returns any
// error returned from closing the Server's underlying Listener(s).
//
// When Shutdown is called, Serve, ListenAndServe, and
// ListenAndServeTLS immediately return ErrServerClosed.
func Shutdown(srv *http.Server) {
	sigint := make(chan os.Signal, 1)
	signal.Notify(sigint, os.Interrupt)
	signal.Notify(sigint, syscall.SIGTERM)
	rec := <-sigint
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	log.Info().Str("signal", rec.String()).Msg("internal/httputil: shutting down servers")
	if err := srv.Shutdown(ctx); err != nil {
		log.Error().Err(err).Msg("internal/httputil: shutdown failed")
	}
}
