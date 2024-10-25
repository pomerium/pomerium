package httputil

import (
	"context"
	"crypto/tls"
	"errors"
	stdlog "log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/urlutil"
)

// NewServer creates a new HTTP server given a set of options, handler, and
// waitgroup. It is the callers responsibility to close the resturned server.
func NewServer(opt *ServerOptions, h http.Handler, wg *sync.WaitGroup) (*http.Server, error) {
	if opt == nil {
		opt = defaultServerOptions
	} else {
		opt.applyServerDefaults()
	}
	sublogger := log.With().
		Str("service", opt.Service).
		Bool("insecure", opt.Insecure).
		Str("addr", opt.Addr).
		Logger()

	if !opt.Insecure && opt.TLSConfig == nil {
		return nil, errors.New("internal/httputil: server must run in insecure mode or have a valid tls config")
	}

	ln, err := net.Listen("tcp", opt.Addr)
	if err != nil {
		return nil, err
	}

	if !opt.Insecure {
		ln = tls.NewListener(ln, opt.TLSConfig)
	}

	// Set up the main server.
	srv := &http.Server{
		ReadHeaderTimeout: opt.ReadHeaderTimeout,
		ReadTimeout:       opt.ReadTimeout,
		WriteTimeout:      opt.WriteTimeout,
		IdleTimeout:       opt.IdleTimeout,
		Handler:           h,
		ErrorLog:          stdlog.New(&log.StdLogWrapper{Logger: &sublogger}, "", 0),
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := srv.Serve(ln); err != http.ErrServerClosed {
			sublogger.Error().Err(err).Msg("internal/httputil: http server crashed")
		}
	}()
	sublogger.Info().Msg("internal/httputil: http server started")

	return srv, nil
}

// RedirectHandler takes an incoming request and redirects to its HTTPS counterpart
func RedirectHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		newURL := new(url.URL)
		*newURL = *r.URL
		newURL.Scheme = "https"
		newURL.Host = urlutil.StripPort(r.Host)

		w.Header().Set("Connection", "close")
		http.Redirect(w, r, newURL.String(), http.StatusMovedPermanently)
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
