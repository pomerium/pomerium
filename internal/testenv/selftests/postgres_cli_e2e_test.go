//go:build postgres_cli_e2e

package selftests_test

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	dockercontainer "github.com/moby/moby/api/types/container"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/postgresidentity"
	"github.com/pomerium/pomerium/internal/testenv"
	"github.com/pomerium/pomerium/internal/testenv/scenarios"
	"github.com/pomerium/pomerium/internal/testenv/snippets"
	"github.com/pomerium/pomerium/internal/testenv/upstreams"
	pomeriumcmd "github.com/pomerium/pomerium/pkg/cmd/pomerium"
	"github.com/pomerium/pomerium/pkg/enterprise/capability"
	configpb "github.com/pomerium/pomerium/pkg/grpc/config"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	sessionpb "github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpcutil"
	"github.com/pomerium/pomerium/pkg/nullable"
	policyparser "github.com/pomerium/pomerium/pkg/policy/parser"
)

const (
	postgresCLIE2EBrowserHelperEnv      = "POMERIUM_POSTGRES_CLI_E2E_BROWSER_HELPER"
	postgresCLIE2EBrowserCoordinatorEnv = "POMERIUM_POSTGRES_CLI_E2E_BROWSER_COORDINATOR"
)

func TestMain(m *testing.M) {
	if os.Getenv(postgresCLIE2EBrowserHelperEnv) == "1" {
		os.Exit(runPostgresCLIBrowserHelper())
	}
	os.Exit(m.Run())
}

func TestPostgresCLILoginBindsAndRunsPSQL(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the deterministic browser helper and Docker host gateway are Linux-specific")
	}
	testcontainers.SkipIfProviderIsNotHealthy(t)
	originalTracerProvider := otel.GetTracerProvider()
	t.Cleanup(func() { otel.SetTracerProvider(originalTracerProvider) })

	cliBinary := os.Getenv("POMERIUM_CLI_BIN")
	require.NotEmpty(t, cliBinary, "POMERIUM_CLI_BIN must name the pomerium-cli binary under test")
	cliBinary, err := filepath.Abs(cliBinary)
	require.NoError(t, err)
	info, err := os.Stat(cliBinary)
	require.NoError(t, err)
	require.Zero(t, info.Mode()&os.ModeType)
	require.NotZero(t, info.Mode()&0o111, "POMERIUM_CLI_BIN must be executable")

	upstreamAddr := startPostgresCLIBackend(t)
	postgresPort := reservePostgresCLIPort(t)
	policy, err := policyparser.ParseYAML(strings.NewReader(`
- allow:
    and:
      - email:
          is: alice@example.com
`))
	require.NoError(t, err)

	env := testenv.New(t)
	env.Add(scenarios.NewIDP([]*scenarios.User{{
		Email:     "alice@example.com",
		FirstName: "Alice",
		LastName:  "Postgres",
	}}))
	env.Add(testenv.ModifierFunc(func(_ context.Context, cfg *config.Config) {
		cfg.Options.InstallationID = "POSTGRES-CLI-E2E-INSTALLATION"
		cfg.Options.PostgresAddr = net.JoinHostPort("0.0.0.0", postgresPort)
		cfg.Options.RuntimeFlags[config.RuntimeFlagPostgres] = true
		cfg.Options.Routes = append(cfg.Options.Routes, config.Policy{
			From: "postgres://db.localhost.pomerium.io",
			To: config.WeightedURLs{{URL: url.URL{
				Scheme: "postgres",
				Host:   upstreamAddr,
			}}},
			RouteOptions: config.RouteOptions{
				Postgres: nullable.From(config.PostgresRouteSettings{
					AuthenticationMode: nullable.From(configpb.PostgresAuthenticationMode_POSTGRES_AUTHENTICATION_MODE_MANAGED),
					Username:           nullable.From("pomeriumtest"),
					Database:           nullable.From("pomeriumtest"),
					Password:           nullable.From("pomeriumtest"),
					UpstreamTlsMode:    nullable.From(configpb.PostgresUpstreamTLSMode_POSTGRES_UPSTREAM_TLS_MODE_DISABLE),
				}),
			},
			Policy: &config.PPLPolicy{Policy: policy},
		})
	}))
	// This test proves the CLI, binding, policy, listener, and PostgreSQL path.
	// It intentionally substitutes only the Enterprise entitlement verifier; it
	// does not prove production Keygen or offline-license evidence verification.
	env.AddOption(pomeriumcmd.WithPostgresManagedVerifierForE2E(postgresCLIE2EVerifier{}))
	defaultTransport := http.DefaultTransport.(*http.Transport).Clone()
	env.Start()
	snippets.WaitStartupComplete(env)
	t.Cleanup(func() { http.DefaultTransport = defaultTransport })
	waitForPostgresCLIListener(t, net.JoinHostPort("127.0.0.1", postgresPort))

	browserCoordinator, browserResult := newPostgresCLIBrowserCoordinator(t, env)
	defer browserCoordinator.Close()
	browserHelper, err := filepath.Abs(os.Args[0])
	require.NoError(t, err)

	cacheHome := filepath.Join(t.TempDir(), "cli-cache")
	controlURL := fmt.Sprintf("https://db.localhost.pomerium.io:%d", env.Ports().ProxyHTTP.Value())
	routeURL := fmt.Sprintf("postgres://db.localhost.pomerium.io:%s/pomeriumtest", postgresPort)
	caFile := filepath.Join(env.TempDir(), "certs", "ca.pem")
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, cliBinary,
		"db", "login", routeURL,
		"--user", "alice",
		"--pomerium-url", controlURL,
		"--ca-file", caFile,
		"--browser-cmd", browserHelper,
	)
	cmd.Env = append(os.Environ(),
		"XDG_CACHE_HOME="+cacheHome,
		postgresCLIE2EBrowserHelperEnv+"=1",
		postgresCLIE2EBrowserCoordinatorEnv+"="+browserCoordinator.URL,
	)
	output, err := cmd.CombinedOutput()
	require.NoErrorf(t, err, "pomerium-cli db login failed:\n%s", output)
	require.Contains(t, string(output), "PostgreSQL login ready until")
	require.Contains(t, string(output), "PGSERVICEFILE=")

	select {
	case err := <-browserResult:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("browser coordinator did not report completion")
	}

	serviceFiles, err := filepath.Glob(filepath.Join(
		cacheHome, "pomerium-cli", "postgres", "login-*", "pg_service.conf"))
	require.NoError(t, err)
	require.Len(t, serviceFiles, 1)
	serviceFile := serviceFiles[0]
	artifactDir := filepath.Dir(serviceFile)

	metadataBytes, err := os.ReadFile(filepath.Join(artifactDir, "binding.json"))
	require.NoError(t, err)
	var metadata struct {
		BindingID string `json:"binding_id"`
		Route     string `json:"route"`
	}
	require.NoError(t, json.Unmarshal(metadataBytes, &metadata))
	require.NotEmpty(t, metadata.BindingID)
	require.Equal(t, "db.localhost.pomerium.io", metadata.Route)

	bindingResponse, err := env.NewDataBrokerServiceClient().Get(t.Context(), &databroker.GetRequest{
		Type: grpcutil.GetTypeURL(new(sessionpb.SessionBinding)),
		Id:   metadata.BindingID,
	})
	require.NoError(t, err)
	require.NotNil(t, bindingResponse.GetRecord())
	var binding sessionpb.SessionBinding
	require.NoError(t, bindingResponse.GetRecord().GetData().UnmarshalTo(&binding))
	require.Equal(t, sessionpb.ProtocolPostgres, binding.GetProtocol())
	require.NotEmpty(t, binding.GetSessionId())
	require.NotEmpty(t, binding.GetUserId())
	require.Equal(t, "db.localhost.pomerium.io", binding.GetDetails()[postgresidentity.DetailRouteHostname])

	// Pomerium installs its traced outbound transport process-wide. The login is
	// complete now. Testenv deliberately installs a panic-on-use global tracer,
	// while the Docker client instruments every daemon request through the global
	// OpenTelemetry provider. Restore neutral process globals for the psql and
	// container-cleanup phase; the original provider is restored last by Cleanup.
	http.DefaultTransport = defaultTransport
	otel.SetTracerProvider(noop.NewTracerProvider())
	runPostgresCLIServicePSQL(t, serviceFile)
}

type postgresCLIE2EVerifier struct{}

func (postgresCLIE2EVerifier) VerifyManagedPostgres(
	context.Context,
	capability.ManagedPostgresAuthority,
) (time.Time, error) {
	return time.Now().Add(time.Hour), nil
}

func runPostgresCLIBrowserHelper() int {
	if len(os.Args) != 2 {
		_, _ = fmt.Fprintln(os.Stderr, "postgres CLI E2E browser helper expected one URL")
		return 2
	}
	coordinator := os.Getenv(postgresCLIE2EBrowserCoordinatorEnv)
	if coordinator == "" {
		_, _ = fmt.Fprintln(os.Stderr, "postgres CLI E2E browser coordinator is unavailable")
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, coordinator, strings.NewReader(os.Args[1]))
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "postgres CLI E2E browser helper request failed")
		return 1
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "postgres CLI E2E browser helper failed")
		return 1
	}
	_, copyErr := io.Copy(io.Discard, resp.Body)
	closeErr := resp.Body.Close()
	if copyErr != nil || closeErr != nil || resp.StatusCode != http.StatusNoContent {
		_, _ = fmt.Fprintln(os.Stderr, "postgres CLI E2E browser helper was rejected")
		return 1
	}
	return 0
}

func newPostgresCLIBrowserCoordinator(
	t *testing.T,
	env testenv.Environment,
) (*httptest.Server, <-chan error) {
	t.Helper()
	result := make(chan error, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 16<<10))
		if err == nil {
			err = drivePostgresCLIBrowser(r.Context(), env, strings.TrimSpace(string(body)))
		}
		result <- err
		if err != nil {
			http.Error(w, "browser flow failed", http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	return server, result
}

func drivePostgresCLIBrowser(ctx context.Context, env testenv.Environment, rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return errors.New("programmatic login returned an invalid browser URL")
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		return err
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    env.ServerCAs(),
	}
	client := &http.Client{Transport: transport, Jar: jar}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return err
	}
	resp, err := upstreams.AuthenticateFlow(ctx, client, req, "alice@example.com", false)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, err = io.Copy(io.Discard, resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("browser callback returned %s", resp.Status)
	}
	return nil
}

func reservePostgresCLIPort(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp4", "0.0.0.0:0")
	require.NoError(t, err)
	_, port, err := net.SplitHostPort(listener.Addr().String())
	require.NoError(t, err)
	require.NoError(t, listener.Close())
	return port
}

func waitForPostgresCLIListener(t *testing.T, address string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	dialer := net.Dialer{Timeout: 250 * time.Millisecond}
	var lastErr error
	for ctx.Err() == nil {
		conn, err := dialer.DialContext(ctx, "tcp", address)
		if err == nil {
			_ = conn.Close()
			return
		}
		lastErr = err
		time.Sleep(50 * time.Millisecond)
	}
	require.NoError(t, lastErr, "native PostgreSQL listener did not start")
}

func startPostgresCLIBackend(t *testing.T) string {
	t.Helper()
	ctx := t.Context()
	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        "postgres:16",
			ExposedPorts: []string{"5432/tcp"},
			Env: map[string]string{
				"POSTGRES_DB":          "pomeriumtest",
				"POSTGRES_PASSWORD":    "pomeriumtest",
				"POSTGRES_USER":        "pomeriumtest",
				"POSTGRES_INITDB_ARGS": "--auth-host=password",
			},
			WaitingFor: wait.ForLog("database system is ready to accept connections").
				WithStartupTimeout(30 * time.Second),
		},
		Started: true,
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, testcontainers.TerminateContainer(container))
	})
	port, err := container.MappedPort(ctx, "5432/tcp")
	require.NoError(t, err)
	loopbackAddress := net.JoinHostPort("127.0.0.1", port.Port())
	conn, err := net.DialTimeout("tcp", loopbackAddress, time.Second)
	require.NoError(t, err, "the E2E requires Docker to publish PostgreSQL on host loopback")
	require.NoError(t, conn.Close())
	return loopbackAddress
}

func runPostgresCLIServicePSQL(t *testing.T, serviceFile string) {
	t.Helper()
	artifactDir := filepath.Dir(serviceFile)
	script := fmt.Sprintf(`
set -eu
hostaddr=$(getent hosts host.docker.internal | awk 'NR == 1 {print $1}')
test -n "$hostaddr"
PGHOSTADDR="$hostaddr" PGSERVICEFILE=%s PGSERVICE=pomerium \
  psql -v ON_ERROR_STOP=1 -At -c "select current_user || '|' || current_database()" | tee /tmp/query.out
grep -qx "pomeriumtest|pomeriumtest" /tmp/query.out
`, postgresCLIShellQuote(serviceFile))

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	container, err := testcontainers.Run(ctx, "postgres:16",
		testcontainers.WithEntrypoint("sh", "-c"),
		testcontainers.WithCmd(script),
		testcontainers.WithHostConfigModifier(func(hostConfig *dockercontainer.HostConfig) {
			hostConfig.ExtraHosts = append(hostConfig.ExtraHosts, "host.docker.internal:host-gateway")
			hostConfig.Binds = append(hostConfig.Binds, artifactDir+":"+artifactDir+":ro")
		}),
		testcontainers.WithWaitStrategy(wait.ForExit().WithExitTimeout(30*time.Second)),
	)
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, testcontainers.TerminateContainer(container))
	})
	logs, err := container.Logs(ctx)
	require.NoError(t, err)
	defer logs.Close()
	output, err := io.ReadAll(logs)
	require.NoError(t, err)
	inspect, err := container.Inspect(ctx)
	require.NoError(t, err)
	require.Equal(t, 0, inspect.State.ExitCode, string(output))
	require.Contains(t, string(output), "pomeriumtest|pomeriumtest")
}

func postgresCLIShellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'"'"'`) + "'"
}
