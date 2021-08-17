package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog/log"
	"golang.org/x/net/publicsuffix"
)

func TestMain(m *testing.M) {
	logger := log.With().Logger()
	ctx := logger.WithContext(context.Background())

	if err := waitForHealthy(ctx); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "services not healthy")
		os.Exit(1)
		return
	}

	status := m.Run()
	os.Exit(status)
}

func getClient() *http.Client {
	jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	if err != nil {
		panic(err)
	}

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
		Jar: jar,
	}
}

func waitForHealthy(ctx context.Context) error {
	client := getClient()
	check := func() error {
		reqCtx, clearTimeout := context.WithTimeout(ctx, time.Second)
		defer clearTimeout()

		req, err := http.NewRequestWithContext(reqCtx, "GET", (&url.URL{
			Scheme: "https",
			Host:   "envoy.localhost.pomerium.io",
			Path:   "/clusters",
		}).String(), nil)
		if err != nil {
			return err
		}

		res, err := client.Do(req)
		if err != nil {
			return err
		}
		defer res.Body.Close()

		var healthy, unhealthy int
		scanner := bufio.NewScanner(res.Body)
		for scanner.Scan() {
			if strings.Contains(scanner.Text(), "::health_flags::") {
				if strings.Contains(scanner.Text(), "::healthy") {
					healthy++
				} else {
					unhealthy++
				}
			}
		}

		if healthy == 0 || unhealthy > 0 {
			return fmt.Errorf("healthy=%d unhealthy=%d", healthy, unhealthy)
		}

		return nil
	}

	ticker := time.NewTicker(time.Second * 3)
	defer ticker.Stop()

	for {
		err := check()
		if err == nil {
			return nil
		}

		log.Ctx(ctx).Info().Err(err).Msg("waiting for healthy")

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func mustParseURL(str string) *url.URL {
	u, err := url.Parse(str)
	if err != nil {
		panic(err)
	}
	return u
}
