package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
)

func main() {
	port := "8443"
	if fromEnv := os.Getenv("PORT"); fromEnv != "" {
		port = fromEnv
	}
	tlsCert := os.Getenv("TLS_CERT")
	tlsKey := os.Getenv("TLS_KEY")
	clientCA := os.Getenv("CLIENT_CA")

	if tlsCert == "" {
		log.Fatal("TLS_CERT environment variable must be set")
	}
	if tlsKey == "" {
		log.Fatal("TLS_KEY environment variable must be set")
	}
	if clientCA == "" {
		log.Fatal("CLIENT_CA environment variable must be set")
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", hello)
	srv := &http.Server{Handler: mux}
	ln, err := newClientCertTLSListener(":"+port, tlsCert, tlsKey, clientCA)
	if err != nil {
		log.Fatalf("failed creating tls listener: %v", err)
	}
	log.Printf("listening on port %s", port)
	log.Fatal(srv.Serve(ln))
}

func hello(w http.ResponseWriter, r *http.Request) {
	log.Printf("Serving request: %s", r.URL.Path)
	fmt.Fprintf(w, "Hello, world!\n")
	fmt.Fprintf(w, "%s %s %s\n", r.Method, r.URL, r.Proto)
	fmt.Fprintf(w, "TLS\n\tServerName: %s\n\tVersion: %d \n\t CipherSuite:%d \n", r.TLS.ServerName, r.TLS.Version, r.TLS.CipherSuite)

	for _, cert := range r.TLS.PeerCertificates {
		fmt.Fprintf(w, "TLSPeerCertificate: Subject %+v\n", cert.Subject)
	}

	if headerIP := r.Header.Get("X-Forwarded-For"); headerIP != "" {
		fmt.Fprintf(w, "Client IP (X-Forwarded-For): %s\n", headerIP)
	}
	fmt.Fprintf(w, "Headers\n")
	for k, v := range r.Header {
		fmt.Fprintf(w, "\t[%s]:\n\t\t%s\n", k, v)
	}
}

func newClientCertTLSListener(addr, tlsCert, tlsKey, clientCA string) (net.Listener, error) {
	caPool, err := decodeCertPoolFromPEM(clientCA)
	if err != nil {
		return nil, err
	}
	cert, err := decodeCertificate(tlsCert, tlsKey)
	if err != nil {
		return nil, err
	}

	tlsConfig := &tls.Config{
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  caPool,
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		},
		PreferServerCipherSuites: true,
		CurvePreferences: []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
		},
		Certificates: []tls.Certificate{*cert},
		NextProtos:   []string{"h2"},
	}
	tlsConfig.BuildNameToCertificate()

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}

	return tls.NewListener(ln, tlsConfig), nil
}

func decodeCertPoolFromPEM(encPemCerts string) (*x509.CertPool, error) {
	pemCerts, err := base64.StdEncoding.DecodeString(encPemCerts)
	if err != nil {
		return nil, fmt.Errorf("couldn't decode pem %v: %w", pemCerts, err)
	}
	certPool := x509.NewCertPool()
	if ok := certPool.AppendCertsFromPEM(pemCerts); !ok {
		return nil, fmt.Errorf("failed to append certs from pem")
	}
	return certPool, nil
}

func decodeCertificate(cert, key string) (*tls.Certificate, error) {
	decodedCert, err := base64.StdEncoding.DecodeString(cert)
	if err != nil {
		return nil, fmt.Errorf("failed to decode certificate cert %v: %w", decodedCert, err)
	}
	decodedKey, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return nil, fmt.Errorf("failed to decode certificate key %v: %w", decodedKey, err)
	}
	x509, err := tls.X509KeyPair(decodedCert, decodedKey)
	return &x509, err
}
