package httputil // import "github.com/pomerium/pomerium/internal/httputil"

import (
	"crypto/tls"
	"time"
)

// ServerOptions contains the configurations settings for a http server.
type ServerOptions struct {
	// Addr specifies the host and port on which the server should serve
	// HTTPS requests. If empty, ":443" is used.
	Addr string

	// TLS certificates to use.
	TLSCertificate *tls.Certificate
	// Timeouts
	ReadHeaderTimeout time.Duration
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
}

var defaultServerOptions = &ServerOptions{
	Addr:              ":443",
	ReadHeaderTimeout: 10 * time.Second,
	ReadTimeout:       30 * time.Second,
	WriteTimeout:      0, // support streaming by default
	IdleTimeout:       5 * time.Minute,
}

func (o *ServerOptions) applyServerDefaults() {
	if o.Addr == "" {
		o.Addr = defaultServerOptions.Addr
	}
	if o.ReadHeaderTimeout == 0 {
		o.ReadHeaderTimeout = defaultServerOptions.ReadHeaderTimeout
	}
	if o.ReadTimeout == 0 {
		o.ReadTimeout = defaultServerOptions.ReadTimeout
	}
	if o.WriteTimeout == 0 {
		o.WriteTimeout = defaultServerOptions.WriteTimeout
	}
	if o.IdleTimeout == 0 {
		o.IdleTimeout = defaultServerOptions.IdleTimeout
	}
}
