package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
)

func main() {
	var certFile, keyFile, mutualAuthCAFile, bindAddr string

	flag.StringVar(&certFile, "cert-file", "", "the tls cert file to use")
	flag.StringVar(&keyFile, "key-file", "", "the tls key file to use")
	flag.StringVar(&mutualAuthCAFile, "mutual-auth-ca-file", "", "if set, require a client cert signed via this ca file")
	flag.StringVar(&bindAddr, "bind-addr", "", "the address to listen on")
	flag.Parse()

	srv := &http.Server{
		Handler: http.HandlerFunc(handle),
	}
	if mutualAuthCAFile != "" {
		caCert, err := ioutil.ReadFile(mutualAuthCAFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to read mutual-auth-ca-file: %v", err)
			os.Exit(1)
		}

		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
		srv.TLSConfig = &tls.Config{
			ClientCAs:  caCertPool,
			ClientAuth: tls.RequireAndVerifyClientCert,
		}
		srv.TLSConfig.BuildNameToCertificate()
	}

	var err error
	if certFile != "" && keyFile != "" {
		if bindAddr == "" {
			bindAddr = ":5443"
		}
		srv.Addr = bindAddr
		fmt.Println("starting server on", bindAddr)
		err = srv.ListenAndServeTLS(certFile, keyFile)
	} else {
		if bindAddr == "" {
			bindAddr = ":5080"
		}
		srv.Addr = bindAddr
		fmt.Println("starting server on", bindAddr)
		err = srv.ListenAndServe()
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to listen and serve: %v", err)
		os.Exit(1)
	}
}

type Result struct {
	Headers    map[string]string `json:"headers"`
	Method     string            `json:"method"`
	Host       string            `json:"host"`
	Port       string            `json:"port"`
	Path       string            `json:"path"`
	Query      string            `json:"query"`
	RequestURI string            `json:"requestURI"`
}

func handle(w http.ResponseWriter, r *http.Request) {
	res := &Result{
		Headers:    map[string]string{},
		Method:     r.Method,
		Host:       r.Host,
		Port:       r.URL.Port(),
		Path:       r.URL.Path,
		Query:      r.URL.RawQuery,
		RequestURI: r.RequestURI,
	}
	for k := range r.Header {
		res.Headers[k] = r.Header.Get(k)
	}
	res.Headers["Host"] = r.Host

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	_ = json.NewEncoder(w).Encode(res)
}
