package httputil // import "github.com/pomerium/pomerium/internal/httputil"

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"
	stdlog "log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pomerium/pomerium/internal/fileutil"
	"github.com/pomerium/pomerium/internal/log"
)

// Options contains the configurations settings for a TLS http server.
type Options struct {
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

var defaultOptions = &Options{
	Addr:              ":https",
	CertFile:          filepath.Join(findKeyDir(), "cert.pem"),
	KeyFile:           filepath.Join(findKeyDir(), "privkey.pem"),
	ReadHeaderTimeout: 10 * time.Second,
	ReadTimeout:       30 * time.Second,
	WriteTimeout:      0, // support streaming by default
	IdleTimeout:       5 * time.Minute,
}

func findKeyDir() string {
	p, err := os.Getwd()
	if err != nil {
		return "."
	}
	return p
}

func (o *Options) applyDefaults() {
	if o.Addr == "" {
		o.Addr = defaultOptions.Addr
	}
	if o.Cert == "" && o.CertFile == "" {
		o.CertFile = defaultOptions.CertFile
	}
	if o.Key == "" && o.KeyFile == "" {
		o.KeyFile = defaultOptions.KeyFile
	}
	if o.ReadHeaderTimeout == 0 {
		o.ReadHeaderTimeout = defaultOptions.ReadHeaderTimeout
	}
	if o.ReadTimeout == 0 {
		o.ReadTimeout = defaultOptions.ReadTimeout
	}
	if o.WriteTimeout == 0 {
		o.WriteTimeout = defaultOptions.WriteTimeout
	}
	if o.IdleTimeout == 0 {
		o.IdleTimeout = defaultOptions.IdleTimeout
	}
}

// ListenAndServeTLS serves the provided handlers by HTTPS
// using the provided options.
func ListenAndServeTLS(opt *Options, httpHandler http.Handler, grpcHandler http.Handler) error {
	if opt == nil {
		opt = defaultOptions
	} else {
		opt.applyDefaults()
	}
	var cert *tls.Certificate
	var err error
	if opt.Cert != "" && opt.Key != "" {
		cert, err = decodeCertificate(opt.Cert, opt.Key)
	} else {
		cert, err = readCertificateFile(opt.CertFile, opt.KeyFile)
	}
	if err != nil {
		return fmt.Errorf("https: failed loading x509 certificate: %v", err)
	}
	config := newDefaultTLSConfig(cert)
	ln, err := net.Listen("tcp", opt.Addr)
	if err != nil {
		return err
	}

	ln = tls.NewListener(ln, config)

	var h http.Handler
	if grpcHandler == nil {
		h = httpHandler
	} else {
		h = grpcHandlerFunc(grpcHandler, httpHandler)
	}
	sublogger := log.With().Str("addr", opt.Addr).Logger()

	// Set up the main server.
	server := &http.Server{
		ReadHeaderTimeout: opt.ReadHeaderTimeout,
		ReadTimeout:       opt.ReadTimeout,
		WriteTimeout:      opt.WriteTimeout,
		IdleTimeout:       opt.IdleTimeout,
		TLSConfig:         config,
		Handler:           h,
		ErrorLog:          stdlog.New(&log.StdLogWrapper{Logger: &sublogger}, "", 0),
	}

	return server.Serve(ln)
}

func decodeCertificate(cert, key string) (*tls.Certificate, error) {
	decodedCert, err := base64.StdEncoding.DecodeString(cert)
	if err != nil {
		return nil, fmt.Errorf("failed to decode certificate cert %v: %v", decodedCert, err)
	}
	decodedKey, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return nil, fmt.Errorf("failed to decode certificate key %v: %v", decodedKey, err)
	}
	x509, err := tls.X509KeyPair(decodedCert, decodedKey)
	return &x509, err
}

func readCertificateFile(certFile, certKeyFile string) (*tls.Certificate, error) {
	certReadable, err := fileutil.IsReadableFile(certFile)
	if err != nil {
		return nil, fmt.Errorf("TLS certificate in %v: %v", certFile, err)
	}
	if !certReadable {
		return nil, fmt.Errorf("certificate file %v not readable", certFile)
	}
	keyReadable, err := fileutil.IsReadableFile(certKeyFile)
	if err != nil {
		return nil, fmt.Errorf("TLS key in %v: %v", certKeyFile, err)
	}
	if !keyReadable {
		return nil, fmt.Errorf("certificate key file %v not readable", certKeyFile)
	}
	cert, err := tls.LoadX509KeyPair(certFile, certKeyFile)
	return &cert, err
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
			tls.CurveP256,
			tls.X25519,
		},
		Certificates: []tls.Certificate{*cert},
		// HTTP/2 must be enabled manually when using http.Serve
		NextProtos: []string{"h2"},
	}
	tlsConfig.BuildNameToCertificate()
	return tlsConfig
}

// grpcHandlerFunc splits request serving between gRPC and HTTPS depending on the request type.
// Requires HTTP/2.
func grpcHandlerFunc(rpcServer http.Handler, other http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ct := r.Header.Get("Content-Type")
		if r.ProtoMajor == 2 && strings.Contains(ct, "application/grpc") {
			rpcServer.ServeHTTP(w, r)
		} else {
			other.ServeHTTP(w, r)
		}
	})
}
