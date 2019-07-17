package httputil // import "github.com/pomerium/pomerium/internal/httputil"

import (
	"os"
	"path/filepath"
	"time"
)

// ServerOptions contains the configurations settings for a http server.
type ServerOptions struct {
	// Addr specifies the host and port on which the server should serve
	// HTTPS requests. If empty, ":https" is used.
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
	Addr:              ":https",
	CertFile:          filepath.Join(findKeyDir(), "cert.pem"),
	KeyFile:           filepath.Join(findKeyDir(), "privkey.pem"),
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
	Addr:              ":http",
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

func findKeyDir() string {
	p, err := os.Getwd()
	if err != nil {
		return "."
	}
	return p
}
