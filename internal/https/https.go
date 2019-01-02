package https // import "github.com/pomerium/pomerium/internal/https"

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/pomerium/pomerium/internal/fileutil"
)

// Options contains the configurations settings for a TLS http server
type Options struct {
	// Addr specifies the host and port on which the server should serve
	// HTTPS requests. If empty, ":https" is used.
	Addr string

	// CertFile and KeyFile specifies the TLS certificates to use.
	CertFile string
	KeyFile  string
}

var defaultOptions = &Options{
	Addr:     ":https",
	CertFile: filepath.Join(findKeyDir(), "cert.pem"),
	KeyFile:  filepath.Join(findKeyDir(), "privkey.pem"),
}

func findKeyDir() string {
	p, err := os.Getwd()
	if err != nil {
		return "."
	}
	return p
}

func (opt *Options) applyDefaults() {
	if opt.Addr == "" {
		opt.Addr = defaultOptions.Addr
	}
	if opt.CertFile == "" {
		opt.CertFile = defaultOptions.CertFile
	}
	if opt.KeyFile == "" {
		opt.KeyFile = defaultOptions.KeyFile
	}
}

// ListenAndServeTLS serves the provided handlers by HTTPS
// using the provided options.
func ListenAndServeTLS(opt *Options, handler http.Handler) error {
	if opt == nil {
		opt = defaultOptions
	} else {
		opt.applyDefaults()
	}

	config, err := newDefaultTLSConfig(opt.CertFile, opt.KeyFile)
	if err != nil {
		return fmt.Errorf("https: setting up TLS config: %v", err)
	}

	ln, err := net.Listen("tcp", opt.Addr)
	if err != nil {
		return err
	}

	ln = tls.NewListener(ln, config)

	// Set up the main server.
	server := &http.Server{
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		// WriteTimeout is set to 0 because it also pertains to
		// streaming replies, e.g., the DirServer.Watch interface.
		WriteTimeout: 0,
		IdleTimeout:  60 * time.Second,
		TLSConfig:    config,
		Handler:      handler,
	}

	return server.Serve(ln)
}

// newDefaultTLSConfig creates a new TLS config based on the certificate files given.
func newDefaultTLSConfig(certFile string, certKeyFile string) (*tls.Config, error) {
	certReadable, err := fileutil.IsReadableFile(certFile)
	if err != nil {
		return nil, fmt.Errorf("TLS certificate in %q: %q", certFile, err)
	}
	if !certReadable {
		return nil, fmt.Errorf("certificate file %q not readable", certFile)
	}
	keyReadable, err := fileutil.IsReadableFile(certKeyFile)
	if err != nil {
		return nil, fmt.Errorf("TLS key in %q: %v", certKeyFile, err)
	}
	if !keyReadable {
		return nil, fmt.Errorf("certificate key file %q not readable", certKeyFile)
	}

	cert, err := tls.LoadX509KeyPair(certFile, certKeyFile)
	if err != nil {
		return nil, err
	}

	tlsConfig := &tls.Config{
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		},
		MinVersion:               tls.VersionTLS12,
		PreferServerCipherSuites: true,
		Certificates:             []tls.Certificate{cert},
	}
	tlsConfig.BuildNameToCertificate()
	return tlsConfig, nil
}
