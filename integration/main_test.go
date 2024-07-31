// Package main contains the pomerium integration tests
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
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
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/require"
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

func getTransport(t testing.TB) http.RoundTripper {
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
	transport := &http.Transport{
		DisableKeepAlives: true,
		TLSClientConfig: &tls.Config{
			RootCAs: rootCAs,
		},
	}
	return loggingRoundTripper{t, transport}
}

func getClient(t testing.TB) *http.Client {
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
		Transport: getTransport(t),
		Jar:       jar,
	}
}

// Returns a new http.Client configured with the same settings as getClient(),
// as well as a pointer to the wrapped http.Transport, so that the
// http.Transport can be easily customized.
func getClientWithTransport(t testing.TB) (*http.Client, *http.Transport) {
	client := getClient(t)
	return client, client.Transport.(loggingRoundTripper).transport.(*http.Transport)
}

func waitForHealthy(ctx context.Context) error {
	client := getClient(nil)
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
			return ctx.Err()
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

func captureLogs(ctx context.Context, out chan<- string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://debug.localhost.pomerium.io/debug/logs", nil)
	if err != nil {
		return err
	}
	client := getClient(nil)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	go func() {
		defer resp.Body.Close()
		defer close(out)
		scan := bufio.NewScanner(resp.Body)
		for scan.Scan() {
			line := scan.Text()
			out <- line
		}
	}()
	return nil
}

type (
	openMap   = map[string]any
	closedMap map[string]any
)

func assertMatchingLogs(t *testing.T, c <-chan string, expectedLogs []map[string]any) {
	t.Helper()
	actualLogs := []map[string]any{}
	for log := range c {
		m := map[string]any{}
		decoder := json.NewDecoder(bytes.NewReader([]byte(log)))
		decoder.UseNumber()
		require.NoError(t, decoder.Decode(&m))
		actualLogs = append(actualLogs, m)
	}

	var match func(expected, actual map[string]any, open bool) (bool, int)
	match = func(expected, actual map[string]any, open bool) (bool, int) {
		score := 0
		for key, value := range expected {
			actualValue, ok := actual[key]
			if !ok {
				return false, score
			}
			score++

			switch actualValue := actualValue.(type) {
			case map[string]any:
				switch value := value.(type) {
				case closedMap:
					ok, s := match(value, actualValue, false)
					score += s * 2
					if !ok {
						return false, score
					}
				case openMap:
					ok, s := match(value, actualValue, true)
					score += s
					if !ok {
						return false, score
					}
				default:
					return false, score
				}
			case string:
				switch value := value.(type) {
				case string:
					if value != actualValue {
						return false, score
					}
					score++
				default:
					return false, score
				}
			case json.Number:
				if fmt.Sprint(value) != actualValue.String() {
					return false, score
				}
				score++
			default:
				panic(fmt.Sprintf("test bug: add check for type %T in assertMatchingLogs", actualValue))
			}
		}
		if !open && len(expected) != len(actual) {
			return false, score
		}
		return true, score
	}

	for _, expectedLog := range expectedLogs {
		found := false

		highScore, highScoreIdxs := 0, []int{}
		for i, actualLog := range actualLogs {
			if ok, score := match(expectedLog, actualLog, true); ok {
				found = true
				break
			} else if score > highScore {
				highScore = score
				highScoreIdxs = []int{i}
			} else if score == highScore {
				highScoreIdxs = append(highScoreIdxs, i)
			}
		}
		if len(highScoreIdxs) > 0 {
			expectedLogBytes, _ := json.MarshalIndent(expectedLog, "", " ")
			if len(highScoreIdxs) == 1 {
				actualLogBytes, _ := json.MarshalIndent(actualLogs[highScoreIdxs[0]], "", " ")
				require.True(t, found, "expected log not found: \n%s\n\nclosest match:\n%s\n",
					string(expectedLogBytes), string(actualLogBytes))
			} else {
				closestMatches := []string{}
				for _, i := range highScoreIdxs {
					bytes, _ := json.MarshalIndent(actualLogs[i], "", " ")
					closestMatches = append(closestMatches, string(bytes))
				}
				require.True(t, found, "expected log not found: \n%s\n\nclosest matches:\n%s\n", string(expectedLogBytes), closestMatches)
			}
		} else {
			expectedLogBytes, _ := json.MarshalIndent(expectedLog, "", " ")
			require.True(t, found, "expected log not found: %s", string(expectedLogBytes))
		}
	}
}
