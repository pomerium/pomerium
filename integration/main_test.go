package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rs/zerolog/log"
)

func TestMain(m *testing.M) {
	logger := log.With().Logger()
	ctx := logger.WithContext(context.Background())

	if err := waitForHealthy(ctx, "authenticate.localhost.pomerium.io"); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "authenticate service not healthy")
		os.Exit(1)
		return
	}

	status := m.Run()
	os.Exit(status)
}

func getClient() *http.Client {
	rootCAs, err := x509.SystemCertPool()
	if err != nil {
		panic(err)
	}

	bs, err := os.ReadFile(filepath.Join(".", "tpl", "files", "ca.pem"))
	if err != nil {
		panic(err)
	}
	_ = rootCAs.AppendCertsFromPEM(bs)

	return &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			DisableKeepAlives: true,
			TLSClientConfig: &tls.Config{
				RootCAs: rootCAs,
			},
		},
	}
}

func waitForHealthy(ctx context.Context, host string) error {
	client := getClient()
	check := func() error {
		reqCtx, clearTimeout := context.WithTimeout(ctx, time.Second)
		defer clearTimeout()

		req, err := http.NewRequestWithContext(reqCtx, "GET", (&url.URL{
			Scheme: "https",
			Host:   host,
			Path:   "/healthz",
		}).String(), nil)
		if err != nil {
			return err
		}

		res, err := client.Do(req)
		if err != nil {
			return err
		}
		_ = res.Body.Close()

		return nil
	}

	ticker := time.NewTicker(time.Second * 3)
	defer ticker.Stop()

	for {
		err := check()
		if err == nil {
			return nil
		}

		log.Ctx(ctx).Info().Msg("waiting for authenticate")

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}
