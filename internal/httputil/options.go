package httputil // import "github.com/pomerium/pomerium/internal/httputil"

import (
	"path/filepath"
	"time"

	"github.com/pomerium/pomerium/internal/fileutil"
)

// ServerOptions contains the configurations settings for a http server.
type ServerOptions struct {
	// Addr specifies the host and port on which the server should serve
	// HTTPS requests. If empty, ":443" is used.
	Addr string

	// TLS certificates to use.
	Cert     string
	Key      string
	CertFile string
	KeyFile  string

	// Timeouts
	ReadHeaderTimeout time.Duration
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
}

var defaultTLSServerOptions = &ServerOptions{
	Addr:              ":443",
	CertFile:          filepath.Join(fileutil.Getwd(), "cert.pem"),
	KeyFile:           filepath.Join(fileutil.Getwd(), "privkey.pem"),
	ReadHeaderTimeout: 10 * time.Second,
	ReadTimeout:       30 * time.Second,
	WriteTimeout:      0, // support streaming by default
	IdleTimeout:       5 * time.Minute,
}

func (o *ServerOptions) applyTLSDefaults() {
	if o.Addr == "" {
		o.Addr = defaultTLSServerOptions.Addr
	}
	if o.Cert == "" && o.CertFile == "" {
		o.CertFile = defaultTLSServerOptions.CertFile
	}
	if o.Key == "" && o.KeyFile == "" {
		o.KeyFile = defaultTLSServerOptions.KeyFile
	}
	if o.ReadHeaderTimeout == 0 {
		o.ReadHeaderTimeout = defaultTLSServerOptions.ReadHeaderTimeout
	}
	if o.ReadTimeout == 0 {
		o.ReadTimeout = defaultTLSServerOptions.ReadTimeout
	}
	if o.WriteTimeout == 0 {
		o.WriteTimeout = defaultTLSServerOptions.WriteTimeout
	}
	if o.IdleTimeout == 0 {
		o.IdleTimeout = defaultTLSServerOptions.IdleTimeout
	}
}

var defaultHTTPServerOptions = &ServerOptions{
	Addr:              ":80",
	ReadHeaderTimeout: 10 * time.Second,
	ReadTimeout:       5 * time.Second,
	WriteTimeout:      5 * time.Second,
	IdleTimeout:       5 * time.Minute,
}

func (o *ServerOptions) applyHTTPDefaults() {
	if o.Addr == "" {
		o.Addr = defaultHTTPServerOptions.Addr
	}
	if o.ReadHeaderTimeout == 0 {
		o.ReadHeaderTimeout = defaultHTTPServerOptions.ReadHeaderTimeout
	}
	if o.ReadTimeout == 0 {
		o.ReadTimeout = defaultHTTPServerOptions.ReadTimeout
	}
	if o.WriteTimeout == 0 {
		o.WriteTimeout = defaultHTTPServerOptions.WriteTimeout
	}
	if o.IdleTimeout == 0 {
		o.IdleTimeout = defaultHTTPServerOptions.IdleTimeout
	}
}
