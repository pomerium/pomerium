package main

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

func TestMain(m *testing.M) {
	status := m.Run()
	os.Exit(status)
}

func getClient() *http.Client {
	rootCAs, err := x509.SystemCertPool()
	if err != nil {
		panic(err)
	}

	bs, err := os.ReadFile(filepath.Join(".", "tpl", "files", "rootCA.pem"))
	if err != nil {
		panic(err)
	}
	_ = rootCAs.AppendCertsFromPEM(bs)

	return &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: rootCAs,
			},
		},
	}
}
