package httputil // import "github.com/pomerium/pomerium/internal/httputil"

import (
	"context"
	"crypto/tls"
	"fmt"
	stdlog "log"
	"net"
	"net/http"
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

	ln, err := net.Listen("tcp", opt.Addr)
	if err != nil {
		return nil, err
	}
	if opt.TLSCertificate != nil {
		ln = tls.NewListener(ln, newDefaultTLSConfig(opt.TLSCertificate))
	}
	sublogger := log.With().Str("addr", opt.Addr).Logger()

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

// newDefaultTLSConfig creates a new TLS config based on the certificate files given.
// See :
// https://wiki.mozilla.org/Security/Server_Side_TLS#Recommended_configurations
// https://blog.cloudflare.com/exposing-go-on-the-internet/
// https://github.com/ssllabs/research/wiki/SSL-and-TLS-Deployment-Best-Practices
// https://github.com/golang/go/blob/df91b8044dbe790c69c16058330f545be069cc1f/src/crypto/tls/common.go#L919
func newDefaultTLSConfig(cert *tls.Certificate) *tls.Config {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		// Prioritize cipher suites sped up by AES-NI (AES-GCM)
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		},
		PreferServerCipherSuites: true,
		// Use curves which have assembly implementations
		CurvePreferences: []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
		},
		Certificates: []tls.Certificate{*cert},
		// HTTP/2 must be enabled manually when using http.Serve
		NextProtos: []string{"h2"},
	}
	tlsConfig.BuildNameToCertificate()
	return tlsConfig
}

// RedirectHandler takes an incoming request and redirects to its HTTPS counterpart
func RedirectHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Connection", "close")
		url := fmt.Sprintf("https://%s", urlutil.StripPort(r.Host))
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
