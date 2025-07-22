//go:build integration

// Package main contains the pomerium integration tests
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/quic-go/quic-go/http3"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"golang.org/x/net/publicsuffix"
)

var IDP, ClusterType, AuthenticateFlow string

func TestMain(m *testing.M) {
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})

	flag.Parse()
	if testing.Verbose() {
		log.Logger = log.Logger.Level(zerolog.DebugLevel)
	} else {
		log.Logger = log.Logger.Level(zerolog.InfoLevel)
	}

	logger := log.With().Logger()
	ctx := logger.WithContext(context.Background())

	if err := waitForHealthy(ctx); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "services not healthy")
		os.Exit(1)
		return
	}

	setClusterInfo(ctx)

	status := m.Run()
	os.Exit(status)
}

type loggingRoundTripper struct {
	t         testing.TB
	transport http.RoundTripper
}

func (l loggingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if l.t != nil {
		l.t.Logf("%s %s", req.Method, req.URL.String())
	}
	return l.transport.RoundTrip(req)
}

func getTransport(t testing.TB, useHTTP3 bool) http.RoundTripper {
	if t != nil {
		t.Helper()
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

	var transport http.RoundTripper
	if useHTTP3 {
		transport = &http3.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: rootCAs,
			},
		}
	} else {
		transport = &http.Transport{
			DisableKeepAlives: true,
			TLSClientConfig: &tls.Config{
				RootCAs: rootCAs,
			},
		}
	}

	return loggingRoundTripper{t, transport}
}

func getClient(t testing.TB, useHTTP3 bool) *http.Client {
	if t != nil {
		t.Helper()
	}

	jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	if err != nil {
		panic(err)
	}

	return &http.Client{
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: getTransport(t, useHTTP3),
		Jar:       jar,
	}
}

// Returns a new http.Client configured with the same settings as getClient(),
// as well as a pointer to the wrapped http.Transport, so that the
// http.Transport can be easily customized.
func getClientWithTransport(t testing.TB) (*http.Client, *http.Transport) {
	client := getClient(t, false)
	return client, client.Transport.(loggingRoundTripper).transport.(*http.Transport)
}

func waitForHealthy(ctx context.Context) error {
	client := getClient(nil, false)
	check := func(endpoint string) error {
		reqCtx, clearTimeout := context.WithTimeout(ctx, time.Second)
		defer clearTimeout()

		req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, endpoint, nil)
		if err != nil {
			return err
		}

		res, err := client.Do(req)
		if err != nil {
			return err
		}
		defer res.Body.Close()

		if res.StatusCode/100 != 2 {
			return fmt.Errorf("%s unavailable: %s", endpoint, res.Status)
		}

		log.Info().Int("status", res.StatusCode).Msgf("%s healthy", endpoint)

		return nil
	}

	ticker := time.NewTicker(time.Second * 3)
	defer ticker.Stop()

	endpoints := []string{
		"https://authenticate.localhost.pomerium.io/.well-known/pomerium/jwks.json",
		"https://mock-idp.localhost.pomerium.io/.well-known/jwks.json",
	}

	for {
		var err error
		for _, endpoint := range endpoints {
			err = check(endpoint)
			if err != nil {
				break
			}
		}
		if err == nil {
			return nil
		}

		log.Ctx(ctx).Info().Err(err).Msg("waiting for healthy")

		select {
		case <-ctx.Done():
			return context.Cause(ctx)
		case <-ticker.C:
		}
	}
}

func setClusterInfo(ctx context.Context) {
	IDP = "oidc"
	ClusterType = "single"
	AuthenticateFlow = "stateful"

	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		log.Error().Err(err).Msg("failed to create docker client")
		return
	}

	containers, err := cli.ContainerList(ctx, container.ListOptions{})
	if err != nil {
		log.Error().Err(err).Msg("failed to retrieve docker containers")
	}
	for _, container := range containers {
		for _, name := range container.Names {
			parts := regexp.MustCompile(`^/(\w+?)-(\w+?)[-_]pomerium.*$`).FindStringSubmatch(name)
			if len(parts) == 3 {
				ClusterType = parts[1]
				AuthenticateFlow = parts[2]
			}
		}
	}

	log.Info().
		Str("idp", IDP).
		Str("cluster-type", ClusterType).
		Str("authenticate-flow", AuthenticateFlow).
		Send()
}

func mustParseURL(str string) *url.URL {
	u, err := url.Parse(str)
	if err != nil {
		panic(err)
	}
	return u
}

func loadCertificate(t *testing.T, certName string) tls.Certificate {
	t.Helper()
	certFile := filepath.Join(".", "tpl", "files", certName+".pem")
	keyFile := filepath.Join(".", "tpl", "files", certName+"-key.pem")
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func testHTTPClient(t *testing.T, f func(t *testing.T, client *http.Client)) {
	t.Helper()
	t.Run("http2", func(t *testing.T) { f(t, getClient(t, false)) })
	t.Run("http3", func(t *testing.T) { f(t, getClient(t, true)) })
}
