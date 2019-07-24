package httputil // import "github.com/pomerium/pomerium/internal/httputil"

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"
	stdlog "log"
	"net"
	"net/http"
	"strings"

	"github.com/pomerium/pomerium/internal/fileutil"
	"github.com/pomerium/pomerium/internal/log"
)

// NewTLSServer creates a new TLS server given a set of options, handlers, and
// optionally a set of gRPC endpoints as well.
// It is the callers responsibility to close the resturned server.
func NewTLSServer(opt *ServerOptions, httpHandler http.Handler, grpcHandler http.Handler) (*http.Server, error) {
	if opt == nil {
		opt = defaultTLSServerOptions
	} else {
		opt.applyTLSDefaults()
	}
	var cert *tls.Certificate
	var err error
	if opt.Cert != "" && opt.Key != "" {
		cert, err = decodeCertificate(opt.Cert, opt.Key)
	} else {
		cert, err = readCertificateFile(opt.CertFile, opt.KeyFile)
	}
	if err != nil {
		return nil, fmt.Errorf("internal/httputil: failed loading x509 certificate: %v", err)
	}
	config := newDefaultTLSConfig(cert)
	ln, err := net.Listen("tcp", opt.Addr)
	if err != nil {
		return nil, err
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
	srv := &http.Server{
		ReadHeaderTimeout: opt.ReadHeaderTimeout,
		ReadTimeout:       opt.ReadTimeout,
		WriteTimeout:      opt.WriteTimeout,
		IdleTimeout:       opt.IdleTimeout,
		TLSConfig:         config,
		Handler:           h,
		ErrorLog:          stdlog.New(&log.StdLogWrapper{Logger: &sublogger}, "", 0),
	}
	go func() {
		if err := srv.Serve(ln); err != http.ErrServerClosed {
			log.Error().Err(err).Msg("internal/httputil: tls server crashed")
		}
	}()

	return srv, nil
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

// grpcHandlerFunc splits request serving between gRPC and HTTPS depending on
// the request type. Requires HTTP/2 to be enabled.
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
