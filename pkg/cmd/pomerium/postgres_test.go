package pomerium

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	dockercontainer "github.com/moby/moby/api/types/container"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/authorize"
	"github.com/pomerium/pomerium/config"
	databrokerserver "github.com/pomerium/pomerium/internal/databroker"
	"github.com/pomerium/pomerium/internal/encoding/jws"
	"github.com/pomerium/pomerium/internal/postgresidentity"
	"github.com/pomerium/pomerium/internal/postgresproxy"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	"github.com/pomerium/pomerium/pkg/databrokerutil/testutil"
	"github.com/pomerium/pomerium/pkg/derivecert"
	"github.com/pomerium/pomerium/pkg/enterprise/capability"
	configpb "github.com/pomerium/pomerium/pkg/grpc/config"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	sessionpb "github.com/pomerium/pomerium/pkg/grpc/session"
	userpb "github.com/pomerium/pomerium/pkg/grpc/user"
	"github.com/pomerium/pomerium/pkg/grpcutil"
	"github.com/pomerium/pomerium/pkg/nullable"
	policyparser "github.com/pomerium/pomerium/pkg/policy/parser"
	"github.com/pomerium/pomerium/pkg/postgresapi"
	"github.com/pomerium/pomerium/pkg/protoutil"
	proxyservice "github.com/pomerium/pomerium/proxy"
)

func TestShouldStartPostgres(t *testing.T) {
	opts := config.NewDefaultOptions()
	require.False(t, shouldStartPostgres(opts))

	opts.PostgresAddr = "127.0.0.1:15432"
	require.False(t, shouldStartPostgres(opts))

	opts.RuntimeFlags[config.RuntimeFlagPostgres] = true
	require.True(t, shouldStartPostgres(opts))
}

func TestPostgresDownstreamTLSRequestsBindingBackedCertificate(t *testing.T) {
	certs := newPostgresRouteTestCerts(t)
	cfg := newPostgresRouteTestConfig(certs)
	cfg.Options.Cert = base64.StdEncoding.EncodeToString(certs.serverCertPEM)
	cfg.Options.Key = base64.StdEncoding.EncodeToString(certs.serverKeyPEM)

	_, sharedKey, err := postgresManagedPostgresAuthority(cfg)
	require.NoError(t, err)
	tlsConfig, err := postgresDownstreamTLSConfig(cfg, sharedKey)
	require.NoError(t, err)
	require.Equal(t, tls.RequestClientCert, tlsConfig.ClientAuth)
	require.Nil(t, tlsConfig.ClientCAs)
}

func TestPostgresListenerDisablesAndReenablesWithConfig(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	certs := newPostgresRouteTestCerts(t)
	cfg := newPostgresRouteTestConfig(certs)
	cfg.Options.SharedKey = cryptutil.NewBase64Key()
	cfg.Options.PostgresAddr = "127.0.0.1:0"
	cfg.Options.RuntimeFlags[config.RuntimeFlagPostgres] = true
	cfg.Options.Cert = base64.StdEncoding.EncodeToString(certs.serverCertPEM)
	cfg.Options.Key = base64.StdEncoding.EncodeToString(certs.serverKeyPEM)
	src := config.NewStaticSource(cfg)
	authz := newPostgresRouteTestAuthorize(t, testutil.NewTestDatabroker(t))

	svc, err := setupPostgres(ctx, src, authz)
	require.NoError(t, err)
	require.NotNil(t, svc)
	runDone := make(chan error, 1)
	go func() {
		runDone <- svc.Run(ctx)
	}()
	t.Cleanup(svc.Stop)
	waitForPostgresListener(t, svc, true)

	next := newPostgresRouteTestConfig(certs)
	next.Options.SharedKey = cfg.Options.SharedKey
	next.Options.PostgresAddr = cfg.Options.PostgresAddr
	next.Options.Cert = cfg.Options.Cert
	next.Options.Key = cfg.Options.Key
	src.SetConfig(ctx, next)

	waitForPostgresListener(t, svc, false)
	select {
	case err := <-runDone:
		t.Fatalf("postgres supervisor exited after disable: %v", err)
	default:
	}
	src.SetConfig(ctx, cfg)
	waitForPostgresListener(t, svc, true)
}

func TestPostgresSupervisorInitialBindFailureRetriesWithoutExiting(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	certs := newPostgresRouteTestCerts(t)
	cfg := postgresSupervisorTestConfig(certs, "first:5432")
	svc, err := setupPostgres(ctx, config.NewStaticSource(cfg), newPostgresRouteTestAuthorize(t, testutil.NewTestDatabroker(t)))
	require.NoError(t, err)

	attempts := make(chan string, 2)
	listener := newPostgresSupervisorTestListener("first:5432")
	var calls atomic.Int32
	svc.listen = func(_ context.Context, _, addr string) (net.Listener, error) {
		attempts <- addr
		if calls.Add(1) == 1 {
			return nil, errors.New("bind failed")
		}
		return listener, nil
	}
	retryRequested := make(chan time.Duration, 1)
	retry := make(chan time.Time, 1)
	svc.after = func(delay time.Duration) <-chan time.Time {
		retryRequested <- delay
		return retry
	}
	svc.reportRunning = func() {}
	svc.reportError = func(error) {}
	svc.reportTerminating = func() {}
	done := make(chan error, 1)
	go func() { done <- svc.Run(ctx) }()

	require.Equal(t, "first:5432", <-attempts)
	require.Equal(t, time.Second, <-retryRequested)
	select {
	case err := <-done:
		t.Fatalf("supervisor exited after initial bind failure: %v", err)
	default:
	}
	retry <- time.Now()
	require.Equal(t, "first:5432", <-attempts)
	<-listener.acceptStarted
	cancel()
	require.NoError(t, <-done)
}

func TestPostgresSupervisorReplacesAddressBeforeClosingLastKnownGood(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	certs := newPostgresRouteTestCerts(t)
	firstCfg := postgresSupervisorTestConfig(certs, "first:5432")
	src := config.NewStaticSource(firstCfg)
	svc, err := setupPostgres(ctx, src, newPostgresRouteTestAuthorize(t, testutil.NewTestDatabroker(t)))
	require.NoError(t, err)
	first := newPostgresSupervisorTestListener("first:5432")
	second := newPostgresSupervisorTestListener("second:5432")
	secondBound := make(chan bool, 1)
	svc.listen = func(_ context.Context, _, addr string) (net.Listener, error) {
		switch addr {
		case "first:5432":
			return first, nil
		case "second:5432":
			select {
			case <-first.closed:
				secondBound <- false
			default:
				secondBound <- true
			}
			return second, nil
		default:
			return nil, errors.New("unexpected address")
		}
	}
	svc.reportRunning = func() {}
	svc.reportError = func(error) {}
	svc.reportTerminating = func() {}
	done := make(chan error, 1)
	go func() { done <- svc.Run(ctx) }()
	<-first.acceptStarted

	secondCfg := postgresSupervisorTestConfig(certs, "second:5432")
	src.SetConfig(ctx, secondCfg)
	require.True(t, <-secondBound, "old listener closed before replacement bind")
	<-second.acceptStarted
	<-first.closed
	require.Same(t, secondCfg, svc.runtime.Load().configGeneration)

	cancel()
	require.NoError(t, <-done)
}

func TestPostgresSupervisorSameAddressPublishesSnapshotWithoutRebind(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	certs := newPostgresRouteTestCerts(t)
	firstCfg := postgresSupervisorTestConfig(certs, "same:5432")
	src := config.NewStaticSource(firstCfg)
	svc, err := setupPostgres(ctx, src, newPostgresRouteTestAuthorize(t, testutil.NewTestDatabroker(t)))
	require.NoError(t, err)
	listener := newPostgresSupervisorTestListener("same:5432")
	var binds atomic.Int32
	svc.listen = func(context.Context, string, string) (net.Listener, error) {
		binds.Add(1)
		return listener, nil
	}
	running := make(chan struct{}, 2)
	svc.reportRunning = func() { running <- struct{}{} }
	svc.reportError = func(error) {}
	svc.reportTerminating = func() {}
	done := make(chan error, 1)
	go func() { done <- svc.Run(ctx) }()
	<-listener.acceptStarted
	<-running

	nextCfg := postgresSupervisorTestConfig(certs, "same:5432")
	nextCfg.Options.LogLevel = config.LogLevelDebug
	src.SetConfig(ctx, nextCfg)
	<-running
	require.Equal(t, int32(1), binds.Load())
	require.Same(t, nextCfg, svc.runtime.Load().configGeneration)
	require.Same(t, listener, svc.currentListener())

	cancel()
	require.NoError(t, <-done)
}

func TestPostgresSupervisorFailedReplacementKeepsLastKnownGood(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	certs := newPostgresRouteTestCerts(t)
	firstCfg := postgresSupervisorTestConfig(certs, "first:5432")
	src := config.NewStaticSource(firstCfg)
	svc, err := setupPostgres(ctx, src, newPostgresRouteTestAuthorize(t, testutil.NewTestDatabroker(t)))
	require.NoError(t, err)
	listener := newPostgresSupervisorTestListener("first:5432")
	replacementAttempted := make(chan struct{})
	svc.listen = func(_ context.Context, _, addr string) (net.Listener, error) {
		if addr == "first:5432" {
			return listener, nil
		}
		close(replacementAttempted)
		return nil, errors.New("replacement bind failed")
	}
	svc.after = func(time.Duration) <-chan time.Time { return make(chan time.Time) }
	reportedError := make(chan struct{}, 1)
	svc.reportRunning = func() {}
	svc.reportError = func(error) { reportedError <- struct{}{} }
	svc.reportTerminating = func() {}
	done := make(chan error, 1)
	go func() { done <- svc.Run(ctx) }()
	<-listener.acceptStarted

	failedCfg := postgresSupervisorTestConfig(certs, "failed:5432")
	src.SetConfig(ctx, failedCfg)
	<-replacementAttempted
	<-reportedError
	require.Same(t, firstCfg, svc.runtime.Load().configGeneration)
	require.Same(t, listener, svc.currentListener())
	select {
	case <-listener.closed:
		t.Fatal("last-known-good listener was closed after failed replacement")
	default:
	}

	cancel()
	require.NoError(t, <-done)
}

func TestPostgresSupervisorAuthorityRotationFailureStopsLastKnownGood(t *testing.T) {
	tests := []struct {
		name       string
		fileBacked bool
		tlsFailure bool
	}{
		{name: "inline authority and bind failure"},
		{name: "file-backed authority and bind failure", fileBacked: true},
		{name: "inline authority and TLS failure", tlsFailure: true},
		{name: "file-backed authority and TLS failure", fileBacked: true, tlsFailure: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			certs := newPostgresRouteTestCerts(t)
			db := testutil.NewTestDatabroker(t)
			seedPostgresRouteTestSession(t, db, certs)
			firstCfg := postgresSupervisorTestConfig(certs, "first:5432")
			var sharedSecretFile string
			if tc.fileBacked {
				sharedSecretFile = filepath.Join(t.TempDir(), "shared-secret")
				require.NoError(t, os.WriteFile(sharedSecretFile, []byte(firstCfg.Options.SharedKey), 0o600))
				firstCfg.Options.SharedKey = ""
				firstCfg.Options.SharedSecretFile = sharedSecretFile
			}
			src := config.NewStaticSource(firstCfg)
			verifier := &fakeManagedPostgresVerifier{expiresAt: time.Now().Add(time.Hour)}
			svc, err := setupPostgres(ctx, src, newPostgresRouteTestAuthorize(t, db), verifier)
			require.NoError(t, err)
			listener := newPostgresSupervisorTestListener("first:5432")
			svc.listen = func(_ context.Context, _, addr string) (net.Listener, error) {
				if addr == "first:5432" {
					return listener, nil
				}
				return nil, errors.New("replacement bind failed")
			}
			svc.after = func(time.Duration) <-chan time.Time { return make(chan time.Time) }
			reportedError := make(chan struct{}, 1)
			svc.reportRunning = func() {}
			svc.reportError = func(error) { reportedError <- struct{}{} }
			svc.reportTerminating = func() {}
			adapter := svc.server.Identity.(*postgresCoreAdapter)
			done := make(chan error, 1)
			go func() { done <- svc.Run(ctx) }()
			<-listener.acceptStarted

			session, err := adapter.Authenticate(t.Context(), postgresRouteTestAuthRequest(certs))
			require.NoError(t, err)
			require.Equal(t, int32(1), verifier.calls.Load())

			failedCfg := postgresSupervisorTestConfig(certs, "failed:5432")
			if tc.fileBacked {
				rotated := base64.StdEncoding.EncodeToString([]byte("abcdefghijklmnopqrstuvwxyzABCDEF"))
				require.NoError(t, os.WriteFile(sharedSecretFile, []byte(rotated), 0o600))
				failedCfg.Options.SharedKey = ""
				failedCfg.Options.SharedSecretFile = sharedSecretFile
			} else {
				failedCfg.Options.InstallationID = "POSTGRES-INSTALLATION-2"
				failedCfg.Options.SharedKey = base64.StdEncoding.EncodeToString([]byte("12345678901234567890123456789012"))
			}
			if tc.tlsFailure {
				failedCfg.Options.PostgresAddr = firstCfg.Options.PostgresAddr
				failedCfg.Options.Cert = "invalid-base64-certificate"
			}
			src.SetConfig(ctx, failedCfg)
			select {
			case <-reportedError:
			case <-time.After(5 * time.Second):
				t.Fatal("postgres supervisor did not report the failed authority rotation")
			}
			waitForPostgresListener(t, svc, false)
			select {
			case <-listener.closed:
			case <-time.After(5 * time.Second):
				t.Fatal("last-known-good listener remained open after authority rotation failed")
			}
			require.Nil(t, svc.runtime.Load())

			_, err = adapter.Authenticate(t.Context(), postgresRouteTestAuthRequest(certs))
			require.ErrorContains(t, err, "runtime configuration is not ready")
			err = adapter.Reauthorize(t.Context(), session)
			require.ErrorContains(t, err, "runtime configuration is not ready")
			require.Equal(t, int32(1), verifier.calls.Load(), "stopped generation must not verify with a new authority")

			cancel()
			require.NoError(t, <-done)
		})
	}
}

func TestPostgresConfigInboxIsNonBlockingLatestWins(t *testing.T) {
	svc := &postgresService{updates: make(chan postgresConfigUpdate, 1)}
	first := context.WithValue(t.Context(), struct{}{}, "first")
	latest := context.WithValue(t.Context(), struct{}{}, "latest")
	svc.enqueue(postgresConfigUpdate{ctx: first})
	svc.enqueue(postgresConfigUpdate{ctx: latest})
	require.Same(t, latest, (<-svc.updates).ctx)
}

func TestPostgresSetupRegistrationRaceReconcilesCurrentSource(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	certs := newPostgresRouteTestCerts(t)
	cfgA := postgresSupervisorTestConfig(certs, "first:5432")
	cfgB := postgresSupervisorTestConfig(certs, "latest:5432")
	cfgB.Options.LogLevel = config.LogLevelDebug
	src := &postgresRegistrationRaceSource{current: cfgA, registrationConfig: cfgB}
	svc, err := setupPostgres(ctx, src, newPostgresRouteTestAuthorize(t, testutil.NewTestDatabroker(t)))
	require.NoError(t, err)

	listener := newPostgresSupervisorTestListener("latest:5432")
	bound := make(chan string, 1)
	svc.listen = func(_ context.Context, _, addr string) (net.Listener, error) {
		bound <- addr
		return listener, nil
	}
	svc.reportRunning = func() {}
	svc.reportError = func(error) {}
	svc.reportTerminating = func() {}
	done := make(chan error, 1)
	go func() { done <- svc.Run(ctx) }()

	require.Equal(t, "latest:5432", <-bound)
	<-listener.acceptStarted
	require.Same(t, cfgB, svc.runtime.Load().configGeneration)
	cancel()
	require.NoError(t, <-done)
}

type postgresRegistrationRaceSource struct {
	mu                 sync.Mutex
	current            *config.Config
	registrationConfig *config.Config
}

func (src *postgresRegistrationRaceSource) GetConfig() *config.Config {
	src.mu.Lock()
	defer src.mu.Unlock()
	return src.current
}

func (src *postgresRegistrationRaceSource) OnConfigChange(ctx context.Context, listener config.ChangeListener) {
	src.mu.Lock()
	src.current = src.registrationConfig
	current := src.current
	src.mu.Unlock()
	listener(ctx, current)
}

func TestPostgresConfigCallbackIsInertAfterShutdown(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	certs := newPostgresRouteTestCerts(t)
	cfg := postgresSupervisorTestConfig(certs, "shutdown:5432")
	src := config.NewStaticSource(cfg)
	svc, err := setupPostgres(ctx, src, newPostgresRouteTestAuthorize(t, testutil.NewTestDatabroker(t)))
	require.NoError(t, err)
	listener := newPostgresSupervisorTestListener("shutdown:5432")
	svc.listen = func(context.Context, string, string) (net.Listener, error) { return listener, nil }
	svc.reportRunning = func() {}
	svc.reportError = func(error) {}
	svc.reportTerminating = func() {}
	done := make(chan error, 1)
	go func() { done <- svc.Run(ctx) }()
	<-listener.acceptStarted
	cancel()
	require.NoError(t, <-done)

	src.SetConfig(t.Context(), postgresSupervisorTestConfig(certs, "after-shutdown:5432"))
	require.Empty(t, svc.updates)
	require.Nil(t, svc.runtime.Load())
}

func postgresSupervisorTestConfig(certs postgresRouteTestCerts, addr string) *config.Config {
	cfg := newPostgresRouteTestConfig(certs)
	cfg.Options.PostgresAddr = addr
	cfg.Options.RuntimeFlags[config.RuntimeFlagPostgres] = true
	cfg.Options.Cert = base64.StdEncoding.EncodeToString(certs.serverCertPEM)
	cfg.Options.Key = base64.StdEncoding.EncodeToString(certs.serverKeyPEM)
	return cfg
}

type postgresSupervisorTestListener struct {
	addr          net.Addr
	acceptStarted chan struct{}
	closed        chan struct{}
	startOnce     sync.Once
	closeOnce     sync.Once
}

func newPostgresSupervisorTestListener(addr string) *postgresSupervisorTestListener {
	return &postgresSupervisorTestListener{
		addr:          postgresSupervisorTestAddr(addr),
		acceptStarted: make(chan struct{}),
		closed:        make(chan struct{}),
	}
}

func (l *postgresSupervisorTestListener) Accept() (net.Conn, error) {
	l.startOnce.Do(func() { close(l.acceptStarted) })
	<-l.closed
	return nil, net.ErrClosed
}

func (l *postgresSupervisorTestListener) Close() error {
	l.closeOnce.Do(func() { close(l.closed) })
	return nil
}

func (l *postgresSupervisorTestListener) Addr() net.Addr { return l.addr }

type postgresSupervisorTestAddr string

func (postgresSupervisorTestAddr) Network() string  { return "tcp" }
func (a postgresSupervisorTestAddr) String() string { return string(a) }

func waitForPostgresListener(t *testing.T, svc *postgresService, want bool) net.Listener {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		listener := svc.currentListener()
		if (listener != nil) == want {
			return listener
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("postgres listener presence never became %t", want)
	return nil
}

func waitForPostgresRuntimeGeneration(
	t *testing.T,
	svc *postgresService,
	want *config.Config,
) net.Listener {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		snapshot := svc.runtime.Load()
		listener := svc.currentListener()
		if snapshot != nil && snapshot.configGeneration == want && listener != nil {
			return listener
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("postgres runtime never published the requested configuration generation")
	return nil
}

func waitForPostgresRouteTestAtomicValue(t *testing.T, value *atomic.Int64, nonzero bool) {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if (value.Load() != 0) == nonzero {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("atomic value nonzero state never became %t", nonzero)
}

func loopbackPostgresRouteTestAddr(t *testing.T, addr net.Addr) string {
	t.Helper()

	_, port, err := net.SplitHostPort(addr.String())
	require.NoError(t, err)
	return net.JoinHostPort("127.0.0.1", port)
}

func reservePostgresRouteTestLoopbackAddr(t *testing.T) string {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := listener.Addr().String()
	require.NoError(t, listener.Close())
	return addr
}

type postgresRouteTestOrderedCloseListener struct {
	net.Listener
	events *atomic.Int64
	closed *atomic.Int64
	once   sync.Once
}

func (l *postgresRouteTestOrderedCloseListener) Close() error {
	l.once.Do(func() {
		l.closed.Store(l.events.Add(1))
	})
	return l.Listener.Close()
}

type postgresRouteTestTrackingListener struct {
	net.Listener
	active *atomic.Int64
}

func (l *postgresRouteTestTrackingListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	l.active.Add(1)
	return &postgresRouteTestTrackingConn{Conn: conn, active: l.active}, nil
}

type postgresRouteTestTrackingConn struct {
	net.Conn
	active *atomic.Int64
	once   sync.Once
}

func (c *postgresRouteTestTrackingConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { c.active.Add(-1) })
	return err
}

func TestPostgresRequestFromSessionUsesSourceIP(t *testing.T) {
	req := postgresRequestFromSession(&postgresproxy.Session{
		ClientAddr: "[2001:db8::1]:54321",
	}, nil, "")
	require.Equal(t, "2001:db8::1", req.SourceAddress)

	req = postgresRequestFromSession(&postgresproxy.Session{
		ClientAddr: "127.0.0.1:54321",
	}, nil, "")
	require.Equal(t, "127.0.0.1", req.SourceAddress)

	req = postgresRequestFromSession(&postgresproxy.Session{
		ClientAddr: "not-a-host-port",
	}, nil, "")
	require.Equal(t, "not-a-host-port", req.SourceAddress)
}

func TestPostgresCoreAdapterRouteCredentialsAndUpstream(t *testing.T) {
	cfg := config.New(config.NewDefaultOptions())
	cfg.Options.Routes = []config.Policy{
		{
			From: "postgres://db.example.com",
			To: config.WeightedURLs{{
				URL: url.URL{
					Scheme: "postgres",
					Host:   "postgres.internal",
				},
			}},
			RouteOptions: config.RouteOptions{
				Postgres: nullable.From(config.PostgresRouteSettings{
					AuthenticationMode: nullable.From(configpb.PostgresAuthenticationMode_POSTGRES_AUTHENTICATION_MODE_MANAGED),
					Username:           nullable.From("dbuser"),
					Database:           nullable.From("appdb"),
					Password:           nullable.From("secret"),
				}),
			},
			TLSUpstreamServerName: "postgres.example.internal",
		},
	}
	runtime := newPostgresCoreAdapterRuntime(cfg)
	adapter := &postgresCoreAdapter{
		runtime:         runtime,
		managedPostgres: &fakeManagedPostgresVerifier{expiresAt: time.Now().Add(time.Hour)},
	}
	session := &postgresproxy.Session{
		Hostname:     "db.example.com",
		RouteID:      runtime.Load().routes["db.example.com"].revision,
		Database:     "clientdb",
		DatabaseUser: "alice",
	}

	creds, err := adapter.UpstreamCredentials(t.Context(), session)
	require.NoError(t, err)
	require.Equal(t, "dbuser", creds.Username)
	require.Equal(t, "secret", creds.Password)
	require.Equal(t, "appdb", creds.Database)

	target, err := adapter.ResolveUpstream(t.Context(), session)
	require.NoError(t, err)
	require.Equal(t, "postgres.internal:5432", target.Addr)
	require.NotNil(t, target.TLSConfig)
	require.Equal(t, "postgres.example.internal", target.TLSConfig.ServerName)
}

func TestPostgresRuntimeDoesNotRereadGlobalCAAfterPublication(t *testing.T) {
	certs := newPostgresRouteTestCerts(t)
	cfg := newPostgresRouteTestConfig(certs)
	cfg.Options.CAFile = certs.caPath
	runtime := newPostgresCoreAdapterRuntime(cfg)
	route := runtime.Load().routes["db.example.com"]
	require.NotNil(t, route.upstream.TLSConfig)
	require.NotNil(t, route.upstream.TLSConfig.RootCAs)

	require.NoError(t, os.WriteFile(certs.caPath, []byte("not-a-ca"), 0o600))
	adapter := &postgresCoreAdapter{runtime: runtime}
	target, err := adapter.ResolveUpstream(t.Context(), &postgresproxy.Session{
		Hostname: "db.example.com",
		RouteID:  route.revision,
	})
	require.NoError(t, err)
	require.NotNil(t, target.TLSConfig.RootCAs)
}

func TestPostgresRuntimeRouteFileRotationChangesMaterialRevision(t *testing.T) {
	first := newPostgresRouteTestCerts(t)
	second := newPostgresRouteTestCerts(t)
	cfg := newPostgresRouteTestConfig(first)
	cfg.Options.Routes[0].TLSCustomCAFile = first.caPath
	cfg.Options.Routes[0].TLSClientCertFile = first.clientCertPath
	cfg.Options.Routes[0].TLSClientKeyFile = first.clientKeyPath
	firstRuntime := newPostgresCoreAdapterRuntime(cfg)
	firstRoute := firstRuntime.Load().routes["db.example.com"]

	secondCertPEM, err := os.ReadFile(second.clientCertPath)
	require.NoError(t, err)
	secondKeyPEM, err := os.ReadFile(second.clientKeyPath)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(first.clientCertPath, secondCertPEM, 0o600))
	require.NoError(t, os.WriteFile(first.clientKeyPath, secondKeyPEM, 0o600))
	require.NoError(t, os.WriteFile(first.caPath, second.caPEM, 0o600))
	secondRuntime := newPostgresCoreAdapterRuntime(cfg)
	secondRoute := secondRuntime.Load().routes["db.example.com"]

	require.NotEqual(t, firstRoute.revision, secondRoute.revision)
	require.NotEqual(t,
		firstRoute.upstream.TLSConfig.Certificates[0].Certificate[0],
		secondRoute.upstream.TLSConfig.Certificates[0].Certificate[0])
	require.False(t,
		firstRoute.upstream.TLSConfig.RootCAs.Equal(secondRoute.upstream.TLSConfig.RootCAs))
}

func TestPostgresFailedRouteFileReloadKeepsCompleteLastKnownGoodSnapshot(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	certs := newPostgresRouteTestCerts(t)
	cfg := postgresSupervisorTestConfig(certs, "same:5432")
	cfg.Options.Routes[0].TLSClientCertFile = certs.clientCertPath
	cfg.Options.Routes[0].TLSClientKeyFile = certs.clientKeyPath
	secretFile := filepath.Join(t.TempDir(), "client-secret")
	require.NoError(t, os.WriteFile(secretFile, []byte("secret-a"), 0o600))
	cfg.Options.ClientSecretFile = secretFile
	cfg.Options.ClientSecret = ""
	src := config.NewStaticSource(cfg)
	svc, err := setupPostgres(ctx, src, newPostgresRouteTestAuthorize(t, testutil.NewTestDatabroker(t)))
	require.NoError(t, err)
	listener := newPostgresSupervisorTestListener("same:5432")
	svc.listen = func(context.Context, string, string) (net.Listener, error) { return listener, nil }
	reportedError := make(chan error, 1)
	svc.reportRunning = func() {}
	svc.reportError = func(err error) { reportedError <- err }
	svc.reportTerminating = func() {}
	done := make(chan error, 1)
	go func() { done <- svc.Run(ctx) }()
	<-listener.acceptStarted
	previous := svc.runtime.Load()
	previousIDP := previous.routes["db.example.com"].expectedIdentityProviderID

	require.NoError(t, os.WriteFile(secretFile, []byte("secret-b"), 0o600))
	require.NoError(t, os.WriteFile(certs.clientKeyPath, []byte("invalid-key"), 0o600))
	src.SetConfig(ctx, cfg)
	select {
	case <-reportedError:
	case <-time.After(5 * time.Second):
		t.Fatal("postgres supervisor did not report invalid route material")
	}
	require.Same(t, previous, svc.runtime.Load())
	require.Equal(t, previousIDP, svc.runtime.Load().routes["db.example.com"].expectedIdentityProviderID)
	options := *cfg.Options
	options.ClientSecret = "secret-b"
	options.ClientSecretFile = ""
	rotatedIDP, err := options.GetIdentityProviderForPolicy(&options.Routes[0])
	require.NoError(t, err)
	require.NotEqual(t, previousIDP, rotatedIDP.GetId())

	cancel()
	require.NoError(t, <-done)
}

func TestPostgresDownstreamCertificateUsesCapturedSharedKey(t *testing.T) {
	cfg := newPostgresRouteTestConfig(newPostgresRouteTestCerts(t))
	cfg.Options.Cert = ""
	cfg.Options.Key = ""
	secretFile := filepath.Join(t.TempDir(), "shared-secret")
	firstKey := []byte("01234567890123456789012345678901")
	secondKey := []byte("abcdefghijklmnopqrstuvwxyzABCDEF")
	require.NoError(t, os.WriteFile(secretFile, []byte(base64.StdEncoding.EncodeToString(firstKey)), 0o600))
	cfg.Options.SharedKey = ""
	cfg.Options.SharedSecretFile = secretFile
	_, capturedKey, err := postgresManagedPostgresAuthority(cfg)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(secretFile, []byte(base64.StdEncoding.EncodeToString(secondKey)), 0o600))

	tlsConfig, err := postgresDownstreamTLSConfig(cfg, capturedKey)
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(tlsConfig.Certificates[0].Certificate[0])
	require.NoError(t, err)
	firstCA, err := derivecert.NewCA(firstKey)
	require.NoError(t, err)
	firstCAPEM, err := firstCA.PEM()
	require.NoError(t, err)
	roots := x509.NewCertPool()
	require.True(t, roots.AppendCertsFromPEM(firstCAPEM.Cert))
	_, err = leaf.Verify(x509.VerifyOptions{Roots: roots})
	require.NoError(t, err)
}

func TestPostgresCoreAdapterAuthorizationErrorsFailClosed(t *testing.T) {
	certs := newPostgresRouteTestCerts(t)
	db := testutil.NewTestDatabroker(t)
	seedPostgresRouteTestSession(t, db, certs)
	cfg := newPostgresRouteTestConfig(certs)
	authz, err := authorize.New(t.Context(), cfg, authorize.WithDataBrokerServiceClient(db))
	require.NoError(t, err)

	adapter := &postgresCoreAdapter{runtime: newPostgresCoreAdapterRuntime(cfg), authz: authz}
	session := &postgresproxy.Session{
		PomeriumSessionID: "POSTGRES-SESSION-1",
		SessionBindingID:  "POSTGRES-BINDING-1",
		UserID:            "POSTGRES-USER-1",
		Hostname:          "db.example.com",
		Database:          "pomeriumtest",
		DatabaseUser:      "alice",
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	err = adapter.AuthorizeSession(ctx, session)
	require.Error(t, err)
}

func TestPostgresUpstreamTLSConfig(t *testing.T) {
	t.Parallel()

	opts := config.NewDefaultOptions()
	t.Run("defaults to verified TLS", func(t *testing.T) {
		upstream := mustParseURL(t, "postgres://postgres.internal:5432")
		policy := managedPostgresTestPolicy(configpb.PostgresUpstreamTLSMode_POSTGRES_UPSTREAM_TLS_MODE_UNSPECIFIED)
		tlsConfig, err := postgresUpstreamTLSConfig(opts, &policy, upstream)
		require.NoError(t, err)
		require.NotNil(t, tlsConfig)
		require.Equal(t, "postgres.internal", tlsConfig.ServerName)
		require.False(t, tlsConfig.InsecureSkipVerify)
	})
	t.Run("explicit plaintext", func(t *testing.T) {
		upstream := mustParseURL(t, "postgres://127.0.0.1:5432")
		policy := managedPostgresTestPolicy(configpb.PostgresUpstreamTLSMode_POSTGRES_UPSTREAM_TLS_MODE_DISABLE)
		tlsConfig, err := postgresUpstreamTLSConfig(opts, &policy, upstream)
		require.NoError(t, err)
		require.Nil(t, tlsConfig)
	})
	t.Run("require skips verification", func(t *testing.T) {
		upstream := mustParseURL(t, "postgres://127.0.0.1:5432")
		policy := managedPostgresTestPolicy(configpb.PostgresUpstreamTLSMode_POSTGRES_UPSTREAM_TLS_MODE_REQUIRE)
		tlsConfig, err := postgresUpstreamTLSConfig(opts, &policy, upstream)
		require.NoError(t, err)
		require.NotNil(t, tlsConfig)
		require.True(t, tlsConfig.InsecureSkipVerify)
	})
}

func newPostgresRouteTestIntegrationConfig(
	t *testing.T,
	upstreamAddr, outboundPort, postgresAddr string,
	certs postgresRouteTestCerts,
) *config.Config {
	t.Helper()

	opts := config.NewDefaultOptions()
	opts.InstallationID = "POSTGRES-INSTALLATION-1"
	opts.SharedKey = cryptutil.NewBase64Key()
	opts.AuthenticateURLString = "https://authenticate.example.com"
	opts.PostgresAddr = postgresAddr
	opts.RuntimeFlags[config.RuntimeFlagPostgres] = true
	opts.RuntimeFlags[config.RuntimeFlagAuthorizeUseSyncedData] = false
	opts.Cert = base64.StdEncoding.EncodeToString(certs.serverCertPEM)
	opts.Key = base64.StdEncoding.EncodeToString(certs.serverKeyPEM)
	opts.DownstreamMTLS.CA = base64.StdEncoding.EncodeToString(certs.caPEM)
	opts.Routes = []config.Policy{{
		From: "postgres://db.example.com",
		To: config.WeightedURLs{{
			URL: url.URL{
				Scheme: "postgres",
				Host:   upstreamAddr,
			},
		}},
		RouteOptions: config.RouteOptions{
			Postgres: nullable.From(config.PostgresRouteSettings{
				AuthenticationMode: nullable.From(configpb.PostgresAuthenticationMode_POSTGRES_AUTHENTICATION_MODE_MANAGED),
				Username:           nullable.From("pomeriumtest"),
				Database:           nullable.From("pomeriumtest"),
				Password:           nullable.From("pomeriumtest"),
				UpstreamTlsMode:    nullable.From(configpb.PostgresUpstreamTLSMode_POSTGRES_UPSTREAM_TLS_MODE_DISABLE),
			}),
		},
		Policy: postgresRouteTestPPL(t, `
- allow:
    and:
      - email:
          is: alice@example.com
`),
	}}
	cfg := config.New(opts)
	cfg.OutboundPort = outboundPort
	return cfg
}

func TestPostgresCoreRouteAuthorizesIdentityAndRelaysQueries(t *testing.T) {
	testcontainers.SkipIfProviderIsNotHealthy(t)

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	upstreamAddr := startPostgresRouteTestPostgres(t)
	execPostgresRouteTestUpstream(t, upstreamAddr, "create table route_guard (id int)")
	certs := newPostgresRouteTestCerts(t)
	db, outboundPort := newPostgresRouteTestDatabroker(t)

	cfg := newPostgresRouteTestIntegrationConfig(t, upstreamAddr, outboundPort, "0.0.0.0:0", certs)
	opts := cfg.Options
	idp, err := opts.GetIdentityProviderForPolicy(&opts.Routes[0])
	require.NoError(t, err)
	webSession := seedPostgresRouteTestWebSession(t, db, idp.GetId())
	proxy, err := proxyservice.New(ctx, cfg)
	require.NoError(t, err)
	bindingID := issuePostgresRouteTestSessionBinding(t, proxy, opts, db, certs, webSession)

	authz, err := authorize.New(ctx, cfg, authorize.WithDataBrokerServiceClient(db))
	require.NoError(t, err)
	verifier := &fakeManagedPostgresVerifier{expiresAt: time.Now().Add(time.Hour)}
	svc, err := setupPostgres(ctx, config.NewStaticSource(cfg), authz, verifier)
	require.NoError(t, err)
	require.NotNil(t, svc)
	// Production capability evidence is signed by a pinned vendor key, so this
	// integration retains a fake only at that boundary. Consumer cryptographic
	// verification remains covered by pkg/enterprise/capability tests.

	runDone := make(chan error, 1)
	go func() {
		runDone <- svc.Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		if listener := svc.currentListener(); listener != nil {
			_ = listener.Close()
		}
		select {
		case err := <-runDone:
			require.NoError(t, err)
		case <-time.After(5 * time.Second):
			t.Fatal("postgres listener did not stop")
		}
	})

	listener := waitForPostgresListener(t, svc, true)
	_, proxyPort, err := net.SplitHostPort(listener.Addr().String())
	require.NoError(t, err)
	proxyAddr := net.JoinHostPort("127.0.0.1", proxyPort)
	conn := connectPostgresRouteTestPGX(t, proxyAddr, certs, "alice", pgx.QueryExecModeSimpleProtocol)
	defer conn.Close(context.Background())

	var currentUser string
	require.NoError(t, conn.QueryRow(ctx, "select current_user").Scan(&currentUser))
	require.Equal(t, "pomeriumtest", currentUser)
	exercisePostgresRouteTestExtendedProtocol(t, proxyAddr, certs)

	_, err = conn.Exec(ctx, "drop table route_guard")
	require.NoError(t, err)
	requirePostgresRouteTestTableMissing(t, upstreamAddr, "route_guard")

	runPostgresRouteTestPSQL(t, proxyAddr, certs)

	metadataSpoof, err := connectPostgresRouteTestPGXErr(t, proxyAddr, certs, "blocked", pgx.QueryExecModeSimpleProtocol)
	require.NoError(t, err)
	defer metadataSpoof.Close(context.Background())
	require.NoError(t, metadataSpoof.QueryRow(ctx, "select current_user").Scan(&currentUser))
	require.Equal(t, "pomeriumtest", currentUser)
	exercisePostgresRouteTestCancellation(t, proxyAddr, upstreamAddr, certs)
	require.GreaterOrEqual(t, verifier.calls.Load(), int32(6), "capability must be re-verified at connection, credential, and query boundaries")

	_, err = db.Put(ctx, &databroker.PutRequest{Records: []*databroker.Record{{
		Type:      grpcutil.GetTypeURL(new(sessionpb.SessionBinding)),
		Id:        bindingID,
		DeletedAt: timestamppb.Now(),
	}}})
	require.NoError(t, err)
	_, err = db.Get(ctx, &databroker.GetRequest{
		Type: grpcutil.GetTypeURL(new(sessionpb.SessionBinding)),
		Id:   bindingID,
	})
	require.Error(t, err, "the issued binding must be tombstoned before reauthorization")

	revokedQueryCtx, stopRevokedQuery := context.WithTimeout(ctx, 5*time.Second)
	defer stopRevokedQuery()
	err = conn.QueryRow(revokedQueryCtx, "select 1").Scan(new(int))
	require.Error(t, err, "an active connection must fail at the first operation boundary after binding revocation")
	revokedConn, err := connectPostgresRouteTestPGXErr(t, proxyAddr, certs, "alice", pgx.QueryExecModeSimpleProtocol)
	if revokedConn != nil {
		defer revokedConn.Close(context.Background())
	}
	require.Error(t, err, "a revoked certificate must not authenticate a new connection")
}

func TestPostgresNativeListenerLifecycleWithRealClients(t *testing.T) {
	testcontainers.SkipIfProviderIsNotHealthy(t)

	ctx, cancelService := context.WithCancel(t.Context())
	upstreamAddr := startPostgresRouteTestPostgres(t)
	certs := newPostgresRouteTestCerts(t)
	rotatedCerts := rotatePostgresRouteTestServerCertificate(t, certs)
	db, outboundPort := newPostgresRouteTestDatabroker(t)
	cfg := newPostgresRouteTestIntegrationConfig(t, upstreamAddr, outboundPort, "127.0.0.1:0", certs)
	idp, err := cfg.Options.GetIdentityProviderForPolicy(&cfg.Options.Routes[0])
	require.NoError(t, err)
	webSession := seedPostgresRouteTestWebSession(t, db, idp.GetId())
	proxy, err := proxyservice.New(ctx, cfg)
	require.NoError(t, err)
	issuePostgresRouteTestSessionBinding(t, proxy, cfg.Options, db, certs, webSession)
	authz, err := authorize.New(ctx, cfg, authorize.WithDataBrokerServiceClient(db))
	require.NoError(t, err)
	src := config.NewStaticSource(cfg)

	// Production capability evidence is signed by a pinned vendor key. Keep the
	// real listener lifecycle below and fake only that cryptographic boundary.
	verifier := &fakeManagedPostgresVerifier{expiresAt: time.Now().Add(time.Hour)}
	svc, err := setupPostgres(ctx, src, authz, verifier)
	require.NoError(t, err)
	require.NotNil(t, svc)

	baseListen := svc.listen
	var (
		listenCalls          atomic.Int32
		lifecycleOrder       atomic.Int64
		replacementBindOrder atomic.Int64
		initialCloseOrder    atomic.Int64
		trackedConnections   atomic.Int64
	)
	svc.listen = func(ctx context.Context, network, addr string) (net.Listener, error) {
		listener, err := baseListen(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		listener = &postgresRouteTestTrackingListener{
			Listener: listener,
			active:   &trackedConnections,
		}
		switch listenCalls.Add(1) {
		case 1:
			return &postgresRouteTestOrderedCloseListener{
				Listener: listener,
				events:   &lifecycleOrder,
				closed:   &initialCloseOrder,
			}, nil
		case 2:
			replacementBindOrder.Store(lifecycleOrder.Add(1))
		}
		return listener, nil
	}

	runDone := make(chan error, 1)
	go func() { runDone <- svc.Run(ctx) }()
	var stopOnce sync.Once
	stopService := func() {
		stopOnce.Do(func() {
			cancelService()
			select {
			case err := <-runDone:
				require.NoError(t, err)
			case <-time.After(5 * time.Second):
				t.Fatal("postgres lifecycle service did not stop")
			}
		})
	}
	t.Cleanup(stopService)

	initialListener := waitForPostgresListener(t, svc, true)
	initialAddr := loopbackPostgresRouteTestAddr(t, initialListener.Addr())
	const heldClientCount = 4
	heldClients := make([]*pgx.Conn, 0, heldClientCount)
	for range heldClientCount {
		conn := connectPostgresRouteTestPGX(t, initialAddr, certs, "alice", pgx.QueryExecModeCacheStatement)
		heldClients = append(heldClients, conn)
		defer conn.Close(context.Background())
	}
	require.GreaterOrEqual(t, trackedConnections.Load(), int64(heldClientCount))

	rotatedCfg := cfg.Clone()
	rotatedCfg.Options.Cert = base64.StdEncoding.EncodeToString(rotatedCerts.serverCertPEM)
	rotatedCfg.Options.Key = base64.StdEncoding.EncodeToString(rotatedCerts.serverKeyPEM)
	rotatedCfg.Options.DownstreamMTLS.CA = base64.StdEncoding.EncodeToString(rotatedCerts.caPEM)
	authz.OnConfigChange(ctx, rotatedCfg)
	src.SetConfig(ctx, rotatedCfg)
	require.Same(t, initialListener, waitForPostgresRuntimeGeneration(t, svc, rotatedCfg))
	require.Equal(t, int32(1), listenCalls.Load(), "same-address TLS rotation must not rebind")

	newTrust := connectPostgresRouteTestPGX(t, initialAddr, rotatedCerts, "alice", pgx.QueryExecModeCacheStatement)
	var one int
	require.NoError(t, newTrust.QueryRow(ctx, "select 1").Scan(&one))
	require.Equal(t, 1, one)
	require.NoError(t, newTrust.Close(context.Background()))
	oldTrust, err := connectPostgresRouteTestPGXErr(t, initialAddr, certs, "alice", pgx.QueryExecModeCacheStatement)
	if oldTrust != nil {
		defer oldTrust.Close(context.Background())
	}
	require.Error(t, err, "new handshakes must reject the previous server CA")
	for _, conn := range heldClients {
		queryCtx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
		err := conn.QueryRow(queryCtx, "select 1").Scan(&one)
		cancel()
		require.NoError(t, err, "same-address TLS rotation must preserve established sessions")
		require.Equal(t, 1, one)
	}

	replacementAddr := reservePostgresRouteTestLoopbackAddr(t)
	replacementCfg := rotatedCfg.Clone()
	replacementCfg.Options.PostgresAddr = replacementAddr
	authz.OnConfigChange(ctx, replacementCfg)
	src.SetConfig(ctx, replacementCfg)
	replacementListener := waitForPostgresRuntimeGeneration(t, svc, replacementCfg)
	require.NotSame(t, initialListener, replacementListener)
	require.Equal(t, replacementAddr, loopbackPostgresRouteTestAddr(t, replacementListener.Addr()))
	replacementProbe := connectPostgresRouteTestPGX(t, replacementAddr, rotatedCerts, "alice", pgx.QueryExecModeCacheStatement)
	require.NoError(t, replacementProbe.QueryRow(ctx, "select 1").Scan(&one))
	require.NoError(t, replacementProbe.Close(context.Background()))
	waitForPostgresRouteTestAtomicValue(t, &initialCloseOrder, true)
	require.Positive(t, replacementBindOrder.Load())
	require.Less(t, replacementBindOrder.Load(), initialCloseOrder.Load(),
		"replacement must bind before the previous listener is closed")
	require.Equal(t, int32(2), listenCalls.Load())
	for _, conn := range heldClients {
		queryCtx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
		err := conn.QueryRow(queryCtx, "select 1").Scan(&one)
		cancel()
		require.Error(t, err, "address replacement must terminate the previous listener generation")
	}

	const loadClientCount = 6
	loadCtx, cancelLoad := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancelLoad()
	loadClients := make([]*pgx.Conn, 0, loadClientCount)
	loadDone := make([]chan error, 0, loadClientCount)
	for i := range loadClientCount {
		conn := connectPostgresRouteTestPGX(t, replacementAddr, rotatedCerts, "alice", pgx.QueryExecModeCacheStatement)
		loadClients = append(loadClients, conn)
		defer conn.Close(context.Background())
		applicationName := fmt.Sprintf("postgres-lifecycle-load-%d", i)
		require.NoError(t, conn.QueryRow(
			loadCtx, "select set_config('application_name', $1, false)", applicationName).Scan(&applicationName))
		done := make(chan error, 1)
		loadDone = append(loadDone, done)
		go func() {
			_, err := conn.Exec(loadCtx, "select pg_sleep(30)")
			done <- err
		}()
	}
	admin := connectPostgresRouteTestUpstream(t, upstreamAddr)
	defer admin.Close(context.Background())
	waitForPostgresRouteTestLoadQueries(t, admin, loadClientCount)
	require.GreaterOrEqual(t, trackedConnections.Load(), int64(loadClientCount))

	stopService()
	for _, done := range loadDone {
		select {
		case err := <-done:
			require.Error(t, err, "shutdown must interrupt active PostgreSQL operations")
		case <-time.After(5 * time.Second):
			t.Fatal("PostgreSQL operation remained blocked after listener shutdown")
		}
	}
	require.Zero(t, trackedConnections.Load(), "all accepted connections must be closed after workers join")
	require.Nil(t, svc.currentListener())
	require.Nil(t, svc.runtime.Load())
	require.True(t, svc.closed.Load())
	svc.stateMu.Lock()
	require.Empty(t, svc.listenAddr)
	svc.stateMu.Unlock()
}

func exercisePostgresRouteTestExtendedProtocol(t *testing.T, addr string, certs postgresRouteTestCerts) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	conn := connectPostgresRouteTestPGX(t, addr, certs, "alice", pgx.QueryExecModeCacheStatement)
	defer conn.Close(context.Background())

	_, err := conn.Prepare(ctx, "route_guard_insert", "insert into route_guard (id) values ($1)")
	require.NoError(t, err)
	_, err = conn.Exec(ctx, "route_guard_insert", 1)
	require.NoError(t, err)

	batch := &pgx.Batch{}
	batch.Queue("route_guard_insert", 2)
	batch.Queue("select count(*) from route_guard")
	results := conn.SendBatch(ctx, batch)
	_, err = results.Exec()
	require.NoError(t, err)
	var rowCount int
	require.NoError(t, results.QueryRow().Scan(&rowCount))
	require.Equal(t, 2, rowCount)
	require.NoError(t, results.Close())

	copied, err := conn.CopyFrom(
		ctx,
		pgx.Identifier{"route_guard"},
		[]string{"id"},
		pgx.CopyFromRows([][]any{{3}, {4}}),
	)
	require.NoError(t, err)
	require.Equal(t, int64(2), copied)
	var idSum int
	require.NoError(t, conn.QueryRow(ctx, "select count(*), sum(id) from route_guard").Scan(&rowCount, &idSum))
	require.Equal(t, 4, rowCount)
	require.Equal(t, 10, idSum)
}

func exercisePostgresRouteTestCancellation(
	t *testing.T,
	proxyAddr, upstreamAddr string,
	certs postgresRouteTestCerts,
) {
	t.Helper()

	target := connectPostgresRouteTestPGX(t, proxyAddr, certs, "alice", pgx.QueryExecModeCacheStatement)
	defer target.Close(context.Background())
	isolation := connectPostgresRouteTestPGX(t, proxyAddr, certs, "alice", pgx.QueryExecModeCacheStatement)
	defer isolation.Close(context.Background())
	admin := connectPostgresRouteTestUpstream(t, upstreamAddr)
	defer admin.Close(context.Background())

	const (
		targetApplication    = "postgres-cancel-target"
		isolationApplication = "postgres-cancel-isolation"
	)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	var applicationName string
	require.NoError(t, target.QueryRow(
		ctx, "select set_config('application_name', $1, false)", targetApplication).Scan(&applicationName))
	require.Equal(t, targetApplication, applicationName)
	require.NoError(t, isolation.QueryRow(
		ctx, "select set_config('application_name', $1, false)", isolationApplication).Scan(&applicationName))
	require.Equal(t, isolationApplication, applicationName)

	targetDone := make(chan error, 1)
	isolationDone := make(chan error, 1)
	go func() {
		_, err := target.Exec(ctx, "select pg_sleep(30)")
		targetDone <- err
	}()
	go func() {
		_, err := isolation.Exec(ctx, "select pg_sleep(2)")
		isolationDone <- err
	}()
	waitForPostgresRouteTestCancelableQueries(t, admin)

	cancelCtx, stopCancel := context.WithTimeout(ctx, 5*time.Second)
	require.NoError(t, target.PgConn().CancelRequest(cancelCtx))
	stopCancel()
	select {
	case err := <-targetDone:
		var pgErr *pgconn.PgError
		require.ErrorAs(t, err, &pgErr)
		require.Equal(t, "57014", pgErr.Code)
	case <-time.After(5 * time.Second):
		t.Fatal("canceled PostgreSQL query did not return")
	}

	var isolationStillActive bool
	checkCtx, stopCheck := context.WithTimeout(ctx, time.Second)
	err := admin.QueryRow(checkCtx, `
select exists (
  select 1
  from pg_stat_activity
  where application_name = 'postgres-cancel-isolation'
    and state = 'active'
    and query like 'select pg_sleep(2)%'
)`).Scan(&isolationStillActive)
	stopCheck()
	require.NoError(t, err)
	require.True(t, isolationStillActive, "canceling one proxy session must not cancel another active session")

	select {
	case err := <-isolationDone:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("isolated PostgreSQL query did not complete")
	}
	var one int
	require.NoError(t, target.QueryRow(ctx, "select 1").Scan(&one))
	require.Equal(t, 1, one)
	require.NoError(t, isolation.QueryRow(ctx, "select 1").Scan(&one))
	require.Equal(t, 1, one)
}

func waitForPostgresRouteTestCancelableQueries(t *testing.T, admin *pgx.Conn) {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	var (
		active  int
		lastErr error
	)
	for time.Now().Before(deadline) {
		queryCtx, cancel := context.WithTimeout(t.Context(), time.Second)
		lastErr = admin.QueryRow(queryCtx, `
select count(*)
from pg_stat_activity
where application_name in ('postgres-cancel-target', 'postgres-cancel-isolation')
  and state = 'active'
  and query like 'select pg_sleep(%'`).Scan(&active)
		cancel()
		if lastErr == nil && active == 2 {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	require.NoError(t, lastErr)
	require.Equal(t, 2, active, "both proxy sessions must reach PostgreSQL before sending CancelRequest")
}

func waitForPostgresRouteTestLoadQueries(t *testing.T, admin *pgx.Conn, want int) {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	var (
		active  int
		lastErr error
	)
	for time.Now().Before(deadline) {
		queryCtx, cancel := context.WithTimeout(t.Context(), time.Second)
		lastErr = admin.QueryRow(queryCtx, `
select count(*)
from pg_stat_activity
where application_name like 'postgres-lifecycle-load-%'
  and state = 'active'
  and query like 'select pg_sleep(30)%'`).Scan(&active)
		cancel()
		if lastErr == nil && active == want {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	require.NoError(t, lastErr)
	require.Equal(t, want, active, "all load clients must reach PostgreSQL before shutdown")
}

func TestPostgresCoreAdapterRejectsInvalidSessionBindings(t *testing.T) {
	cases := []struct {
		name         string
		mutate       func(*sessionpb.SessionBinding, *sessionpb.Session, *databroker.Record, *databroker.Record)
		authenticate bool
		wantErr      string
	}{
		{
			name: "wrong protocol",
			mutate: func(binding *sessionpb.SessionBinding, _ *sessionpb.Session, _, _ *databroker.Record) {
				binding.Protocol = sessionpb.ProtocolSSH
			},
			wantErr: "invalid protocol",
		},
		{
			name: "missing binding session id",
			mutate: func(binding *sessionpb.SessionBinding, _ *sessionpb.Session, _, _ *databroker.Record) {
				binding.SessionId = ""
			},
			wantErr: "identity is incomplete",
		},
		{
			name: "missing binding user id",
			mutate: func(binding *sessionpb.SessionBinding, _ *sessionpb.Session, _, _ *databroker.Record) {
				binding.UserId = ""
			},
			wantErr: "identity is incomplete",
		},
		{
			name: "missing binding issued at",
			mutate: func(binding *sessionpb.SessionBinding, _ *sessionpb.Session, _, _ *databroker.Record) {
				binding.IssuedAt = nil
			},
			wantErr: "issued_at is required",
		},
		{
			name: "zero binding issued at",
			mutate: func(binding *sessionpb.SessionBinding, _ *sessionpb.Session, _, _ *databroker.Record) {
				binding.IssuedAt = timestamppb.New(time.Unix(0, 0))
			},
			wantErr: "issued_at is required",
		},
		{
			name: "invalid binding issued at",
			mutate: func(binding *sessionpb.SessionBinding, _ *sessionpb.Session, _, _ *databroker.Record) {
				binding.IssuedAt = &timestamppb.Timestamp{Seconds: 253402300800}
			},
			wantErr: "issued_at is invalid",
		},
		{
			name: "binding issued materially in future",
			mutate: func(binding *sessionpb.SessionBinding, _ *sessionpb.Session, _, _ *databroker.Record) {
				binding.IssuedAt = timestamppb.New(time.Now().Add(2 * postgresSessionBindingClockSkew))
			},
			wantErr: "issued_at is in the future",
		},
		{
			name: "missing binding expiry",
			mutate: func(binding *sessionpb.SessionBinding, _ *sessionpb.Session, _, _ *databroker.Record) {
				binding.ExpiresAt = nil
			},
			wantErr: "expiry is required",
		},
		{
			name: "zero binding expiry",
			mutate: func(binding *sessionpb.SessionBinding, _ *sessionpb.Session, _, _ *databroker.Record) {
				binding.ExpiresAt = timestamppb.New(time.Unix(0, 0))
			},
			wantErr: "expiry is required",
		},
		{
			name: "invalid binding expiry",
			mutate: func(binding *sessionpb.SessionBinding, _ *sessionpb.Session, _, _ *databroker.Record) {
				binding.ExpiresAt = &timestamppb.Timestamp{Seconds: 253402300800}
			},
			wantErr: "expiry is invalid",
		},
		{
			name: "binding expiry precedes issue",
			mutate: func(binding *sessionpb.SessionBinding, _ *sessionpb.Session, _, _ *databroker.Record) {
				binding.IssuedAt = timestamppb.New(time.Now().Add(30 * time.Second))
				binding.ExpiresAt = timestamppb.New(time.Now().Add(20 * time.Second))
			},
			wantErr: "expiry precedes issued_at",
		},
		{
			name: "expired binding",
			mutate: func(binding *sessionpb.SessionBinding, _ *sessionpb.Session, _, _ *databroker.Record) {
				binding.ExpiresAt = timestamppb.New(time.Now().Add(-time.Minute))
			},
			wantErr: "expired",
		},
		{
			name: "missing binding route",
			mutate: func(binding *sessionpb.SessionBinding, _ *sessionpb.Session, _, _ *databroker.Record) {
				delete(binding.Details, postgresidentity.DetailRouteHostname)
			},
			wantErr: "route is required",
		},
		{
			name: "deleted binding",
			mutate: func(_ *sessionpb.SessionBinding, _ *sessionpb.Session, bindingRecord, _ *databroker.Record) {
				bindingRecord.DeletedAt = timestamppb.Now()
			},
			wantErr: "record not found",
		},
		{
			name: "deleted web session",
			mutate: func(_ *sessionpb.SessionBinding, _ *sessionpb.Session, _, sessionRecord *databroker.Record) {
				sessionRecord.DeletedAt = timestamppb.Now()
			},
			wantErr: "record not found",
		},
		{
			name: "expired web session",
			mutate: func(_ *sessionpb.SessionBinding, webSession *sessionpb.Session, _, _ *databroker.Record) {
				webSession.ExpiresAt = timestamppb.New(time.Now().Add(-time.Minute))
			},
			wantErr: "session expired",
		},
		{
			name: "expired web session oauth token",
			mutate: func(_ *sessionpb.SessionBinding, webSession *sessionpb.Session, _, _ *databroker.Record) {
				webSession.OauthToken = &sessionpb.OAuthToken{ExpiresAt: timestamppb.New(time.Now().Add(-time.Minute))}
				webSession.RefreshDisabled = true
			},
			wantErr: "access_token expired",
		},
		{
			name: "missing web session id",
			mutate: func(_ *sessionpb.SessionBinding, webSession *sessionpb.Session, _, _ *databroker.Record) {
				webSession.Id = ""
			},
			wantErr: "identity is incomplete",
		},
		{
			name: "missing web session user id",
			mutate: func(_ *sessionpb.SessionBinding, webSession *sessionpb.Session, _, _ *databroker.Record) {
				webSession.UserId = ""
			},
			wantErr: "identity is incomplete",
		},
		{
			name: "missing web session identity provider",
			mutate: func(_ *sessionpb.SessionBinding, webSession *sessionpb.Session, _, _ *databroker.Record) {
				webSession.IdpId = ""
			},
			wantErr: "identity is incomplete",
		},
		{
			name: "web session id mismatch",
			mutate: func(_ *sessionpb.SessionBinding, webSession *sessionpb.Session, _, _ *databroker.Record) {
				webSession.Id = "POSTGRES-SESSION-OTHER"
			},
			wantErr: "no longer matches",
		},
		{
			name: "web session user mismatch",
			mutate: func(_ *sessionpb.SessionBinding, webSession *sessionpb.Session, _, _ *databroker.Record) {
				webSession.UserId = "POSTGRES-USER-OTHER"
			},
			wantErr: "no longer matches",
		},
		{
			name: "binding user mismatch",
			mutate: func(binding *sessionpb.SessionBinding, _ *sessionpb.Session, _, _ *databroker.Record) {
				binding.UserId = "POSTGRES-USER-OTHER"
			},
			wantErr: "no longer matches",
		},
		{
			name: "binding route mismatch",
			mutate: func(binding *sessionpb.SessionBinding, _ *sessionpb.Session, _, _ *databroker.Record) {
				binding.Details[postgresidentity.DetailRouteHostname] = "other.example.com"
			},
			authenticate: true,
			wantErr:      "different route",
		},
	}

	t.Run("missing binding id", func(t *testing.T) {
		adapter := new(postgresCoreAdapter)
		_, _, _, err := adapter.resolveSessionBinding(t.Context(), "")
		require.ErrorContains(t, err, "binding is required")
	})

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			certs := newPostgresRouteTestCerts(t)
			db := testutil.NewTestDatabroker(t)
			bindingID := putPostgresRouteTestSessionBinding(t, db, certs, tc.mutate)
			authz := newPostgresRouteTestAuthorize(t, db)
			adapter := &postgresCoreAdapter{
				runtime:         newPostgresCoreAdapterRuntime(newPostgresRouteTestConfig(certs)),
				authz:           authz,
				managedPostgres: &fakeManagedPostgresVerifier{expiresAt: time.Now().Add(time.Hour)},
			}

			_, _, _, err := adapter.resolveSessionBinding(t.Context(), bindingID)
			if tc.authenticate {
				_, err = adapter.Authenticate(t.Context(), postgresRouteTestAuthRequest(certs))
			}
			require.Error(t, err)
			require.Contains(t, err.Error(), tc.wantErr)
		})
	}
}

func TestPostgresCoreAdapterAcceptsBindingClockSkewAndEpochWebExpiry(t *testing.T) {
	now := time.Now()
	certs := newPostgresRouteTestCerts(t)
	db := testutil.NewTestDatabroker(t)
	putPostgresRouteTestSessionBinding(t, db, certs, func(binding *sessionpb.SessionBinding, webSession *sessionpb.Session, _, _ *databroker.Record) {
		binding.IssuedAt = timestamppb.New(now.Add(postgresSessionBindingClockSkew / 2))
		webSession.ExpiresAt = timestamppb.New(time.Unix(0, 0))
	})
	authz := newPostgresRouteTestAuthorize(t, db)
	adapter := &postgresCoreAdapter{
		runtime:         newPostgresCoreAdapterRuntime(newPostgresRouteTestConfig(certs)),
		authz:           authz,
		managedPostgres: &fakeManagedPostgresVerifier{expiresAt: now.Add(time.Hour)},
	}

	session, err := adapter.Authenticate(t.Context(), postgresRouteTestAuthRequest(certs))
	require.NoError(t, err)
	require.WithinDuration(t, now.Add(time.Hour), session.ExpiresAt, time.Second)
}

func TestPostgresCoreAdapterUsesEarliestPersistentAuthoritativeExpiry(t *testing.T) {
	tests := []struct {
		name             string
		capabilityOffset time.Duration
		bindingOffset    time.Duration
		sessionOffset    time.Duration
		wantOffset       time.Duration
	}{
		{"renewable capability lease is not a socket deadline", 5 * time.Minute, 20 * time.Minute, 30 * time.Minute, 20 * time.Minute},
		{"binding", 30 * time.Minute, 10 * time.Minute, 20 * time.Minute, 10 * time.Minute},
		{"web session", 30 * time.Minute, 20 * time.Minute, 10 * time.Minute, 10 * time.Minute},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			now := time.Now()
			certs := newPostgresRouteTestCerts(t)
			db := testutil.NewTestDatabroker(t)
			putPostgresRouteTestSessionBinding(t, db, certs, func(binding *sessionpb.SessionBinding, webSession *sessionpb.Session, _, _ *databroker.Record) {
				binding.ExpiresAt = timestamppb.New(now.Add(tc.bindingOffset))
				webSession.ExpiresAt = timestamppb.New(now.Add(tc.sessionOffset))
			})
			authz := newPostgresRouteTestAuthorize(t, db)
			adapter := &postgresCoreAdapter{
				runtime:         newPostgresCoreAdapterRuntime(newPostgresRouteTestConfig(certs)),
				authz:           authz,
				managedPostgres: &fakeManagedPostgresVerifier{expiresAt: now.Add(tc.capabilityOffset)},
			}

			session, err := adapter.Authenticate(t.Context(), postgresRouteTestAuthRequest(certs))
			require.NoError(t, err)
			require.WithinDuration(t, now.Add(tc.wantOffset), session.ExpiresAt, time.Second)
		})
	}
}

func TestPostgresCoreAdapterRenewsCapabilityWithoutFreezingLeaseIntoSocketDeadline(t *testing.T) {
	now := time.Now()
	certs := newPostgresRouteTestCerts(t)
	db := testutil.NewTestDatabroker(t)
	seedPostgresRouteTestSession(t, db, certs)
	cfg := newPostgresRouteTestConfig(certs)
	verifier := &fakeManagedPostgresVerifier{expiresAt: now.Add(5 * time.Minute)}
	adapter := &postgresCoreAdapter{
		runtime:         newPostgresCoreAdapterRuntime(cfg),
		authz:           newPostgresRouteTestAuthorize(t, db),
		managedPostgres: verifier,
	}
	session, err := adapter.Authenticate(t.Context(), postgresRouteTestAuthRequest(certs))
	require.NoError(t, err)
	require.WithinDuration(t, now.Add(time.Hour), session.ExpiresAt, time.Second)

	verifier.err = errors.New("renewal stopped")
	require.ErrorIs(t, adapter.Reauthorize(t.Context(), session), capability.ErrDenied)
}

func TestPostgresCoreAdapterManagedCapabilityDenialIsGenericAtEveryBoundary(t *testing.T) {
	const canary = "managed-capability-sensitive-canary"
	certs := newPostgresRouteTestCerts(t)
	db := testutil.NewTestDatabroker(t)
	seedPostgresRouteTestSession(t, db, certs)
	authz := newPostgresRouteTestAuthorize(t, db)
	cfg := newPostgresRouteTestConfig(certs)
	routeID, err := cfg.Options.Routes[0].PostgresRouteRevision()
	require.NoError(t, err)
	fingerprint := sha256.Sum256(certs.clientCert.Certificate[0])
	adapter := &postgresCoreAdapter{
		runtime:         newPostgresCoreAdapterRuntime(cfg),
		authz:           authz,
		managedPostgres: &fakeManagedPostgresVerifier{err: errors.New(canary)},
	}
	session := &postgresproxy.Session{
		PomeriumSessionID: "POSTGRES-SESSION-1",
		SessionBindingID:  postgresidentity.BindingIDFromFingerprint(fingerprint[:]),
		UserID:            "POSTGRES-USER-1",
		RouteID:           routeID,
		Hostname:          "db.example.com",
	}

	_, err = adapter.Authenticate(t.Context(), postgresRouteTestAuthRequest(certs))
	require.ErrorIs(t, err, capability.ErrDenied)
	require.NotContains(t, err.Error(), canary)
	_, err = adapter.UpstreamCredentials(t.Context(), session)
	require.ErrorIs(t, err, capability.ErrDenied)
	require.NotContains(t, err.Error(), canary)
	err = adapter.Reauthorize(t.Context(), session)
	require.ErrorIs(t, err, capability.ErrDenied)
	require.NotContains(t, err.Error(), canary)
}

func TestPostgresCoreAdapterReauthorizeRejectsBindingUserMismatch(t *testing.T) {
	certs := newPostgresRouteTestCerts(t)
	db := testutil.NewTestDatabroker(t)
	bindingID := putPostgresRouteTestSessionBinding(t, db, certs, func(binding *sessionpb.SessionBinding, _ *sessionpb.Session, _, _ *databroker.Record) {
		binding.UserId = "POSTGRES-USER-OTHER"
	})
	authz := newPostgresRouteTestAuthorize(t, db)
	cfg := newPostgresRouteTestConfig(certs)
	routeID, err := cfg.Options.Routes[0].PostgresRouteRevision()
	require.NoError(t, err)
	adapter := &postgresCoreAdapter{
		runtime:         newPostgresCoreAdapterRuntime(cfg),
		authz:           authz,
		managedPostgres: &fakeManagedPostgresVerifier{expiresAt: time.Now().Add(time.Hour)},
	}

	err = adapter.Reauthorize(t.Context(), &postgresproxy.Session{
		PomeriumSessionID: "POSTGRES-SESSION-1",
		SessionBindingID:  bindingID,
		UserID:            "POSTGRES-USER-1",
		RouteID:           routeID,
		Hostname:          "db.example.com",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "no longer matches")
}

func TestPostgresCoreAdapterReauthorizeRejectsBindingRouteMismatch(t *testing.T) {
	certs := newPostgresRouteTestCerts(t)
	db := testutil.NewTestDatabroker(t)
	bindingID := putPostgresRouteTestSessionBinding(t, db, certs, func(binding *sessionpb.SessionBinding, _ *sessionpb.Session, _, _ *databroker.Record) {
		binding.Details[postgresidentity.DetailRouteHostname] = "other.example.com"
	})
	authz := newPostgresRouteTestAuthorize(t, db)
	cfg := newPostgresRouteTestConfig(certs)
	routeID, err := cfg.Options.Routes[0].PostgresRouteRevision()
	require.NoError(t, err)
	adapter := &postgresCoreAdapter{
		runtime:         newPostgresCoreAdapterRuntime(cfg),
		authz:           authz,
		managedPostgres: &fakeManagedPostgresVerifier{expiresAt: time.Now().Add(time.Hour)},
	}

	err = adapter.Reauthorize(t.Context(), &postgresproxy.Session{
		PomeriumSessionID: "POSTGRES-SESSION-1",
		SessionBindingID:  bindingID,
		UserID:            "POSTGRES-USER-1",
		RouteID:           routeID,
		Hostname:          "db.example.com",
	})
	require.ErrorContains(t, err, "no longer matches the route")
}

func TestPostgresCoreAdapterRejectsRotatedRouteIdentityProvider(t *testing.T) {
	tests := []struct {
		name   string
		rotate func(*config.Config)
	}{
		{
			name: "route-specific provider",
			rotate: func(cfg *config.Config) {
				cfg.Options.Routes[0].IDPClientID = "rotated-route-client-id"
			},
		},
		{
			name: "default provider",
			rotate: func(cfg *config.Config) {
				cfg.Options.ClientID = "rotated-default-client-id"
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			certs := newPostgresRouteTestCerts(t)
			db := testutil.NewTestDatabroker(t)
			seedPostgresRouteTestSession(t, db, certs)
			oldCfg := newPostgresRouteTestConfig(certs)
			rotatedCfg := newPostgresRouteTestConfig(certs)
			tc.rotate(rotatedCfg)
			oldRevision, err := oldCfg.Options.Routes[0].PostgresRouteRevision()
			require.NoError(t, err)
			rotatedRevision, err := rotatedCfg.Options.Routes[0].PostgresRouteRevision()
			require.NoError(t, err)
			require.Equal(t, oldRevision, rotatedRevision, "IdP validation must not rely on the route revision")

			runtime := newPostgresCoreAdapterRuntime(rotatedCfg)
			adapter := &postgresCoreAdapter{
				runtime:         runtime,
				authz:           newPostgresRouteTestAuthorize(t, db),
				managedPostgres: &fakeManagedPostgresVerifier{expiresAt: time.Now().Add(time.Hour)},
			}
			_, err = adapter.Authenticate(t.Context(), postgresRouteTestAuthRequest(certs))
			require.ErrorContains(t, err, "identity provider no longer matches the route")

			runtime = newPostgresCoreAdapterRuntime(oldCfg)
			adapter.runtime = runtime
			session, err := adapter.Authenticate(t.Context(), postgresRouteTestAuthRequest(certs))
			require.NoError(t, err)
			runtime = newPostgresCoreAdapterRuntime(rotatedCfg)
			adapter.runtime = runtime
			err = adapter.Reauthorize(t.Context(), session)
			require.ErrorContains(t, err, "route changed during session")
		})
	}
}

func newPostgresRouteTestDatabroker(t *testing.T) (databroker.DataBrokerServiceClient, string) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	backend := databrokerserver.NewBackendServer(noop.NewTracerProvider())
	server := grpc.NewServer()
	databroker.RegisterDataBrokerServiceServer(server, backend)
	serveDone := make(chan error, 1)
	go func() {
		serveDone <- server.Serve(listener)
	}()

	conn, err := grpc.NewClient(listener.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, conn.Close())
		server.Stop()
		backend.Stop()
		serveErr := <-serveDone
		require.True(t, serveErr == nil || errors.Is(serveErr, grpc.ErrServerStopped), serveErr)
	})

	_, port, err := net.SplitHostPort(listener.Addr().String())
	require.NoError(t, err)
	return databroker.NewDataBrokerServiceClient(conn), port
}

func seedPostgresRouteTestWebSession(
	t *testing.T,
	client databroker.DataBrokerServiceClient,
	idpID string,
) *sessionpb.Session {
	t.Helper()

	now := time.Now()
	webSession := &sessionpb.Session{
		Id:        "POSTGRES-SESSION-1",
		UserId:    "POSTGRES-USER-1",
		IdpId:     idpID,
		IssuedAt:  timestamppb.New(now.Add(-time.Minute)),
		ExpiresAt: timestamppb.New(now.Add(time.Hour)),
	}
	_, err := client.Put(t.Context(), &databroker.PutRequest{Records: []*databroker.Record{
		databroker.NewRecord(webSession),
		databroker.NewRecord(&userpb.User{
			Id:    webSession.UserId,
			Email: "alice@example.com",
		}),
	}})
	require.NoError(t, err)
	return webSession
}

func issuePostgresRouteTestSessionBinding(
	t *testing.T,
	proxy *proxyservice.Proxy,
	opts *config.Options,
	client databroker.DataBrokerServiceClient,
	certs postgresRouteTestCerts,
	webSession *sessionpb.Session,
) string {
	t.Helper()

	authenticateURL, err := opts.GetAuthenticateURL()
	require.NoError(t, err)
	issuer := authenticateURL.Host
	handle := &sessionpb.Handle{
		Id:                 webSession.Id,
		UserId:             webSession.UserId,
		IdentityProviderId: webSession.IdpId,
		Iss:                &issuer,
		Aud:                []string{"control.example.com"},
		Iat:                timestamppb.Now(),
	}
	sharedKey, err := opts.GetSharedKey()
	require.NoError(t, err)
	signer, err := jws.NewHS256Signer(sharedKey)
	require.NoError(t, err)
	encodedHandle, err := signer.Marshal(handle)
	require.NoError(t, err)
	rawSessionHandle := string(encodedHandle)

	require.Len(t, certs.clientCert.Certificate, 1)
	clientCertificate, err := x509.ParseCertificate(certs.clientCert.Certificate[0])
	require.NoError(t, err)
	clientPrivateKey, ok := certs.clientCert.PrivateKey.(ed25519.PrivateKey)
	require.True(t, ok)
	proofMessage, err := postgresapi.SessionBindingProofMessage(
		"db.example.com", rawSessionHandle, clientCertificate.Raw)
	require.NoError(t, err)
	requestBody, err := json.Marshal(postgresapi.CreateSessionBindingRequest{
		RouteHost: "db.example.com",
		CertificatePEM: string(pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: clientCertificate.Raw,
		})),
		ProofSignature: base64.RawStdEncoding.EncodeToString(ed25519.Sign(clientPrivateKey, proofMessage)),
	})
	require.NoError(t, err)

	request := httptest.NewRequest(
		http.MethodPost,
		"https://control.example.com"+postgresapi.SessionBindingsPath,
		bytes.NewReader(requestBody),
	)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer Pomerium-"+rawSessionHandle)
	response := httptest.NewRecorder()
	proxy.ServeHTTP(response, request)
	require.Equal(t, http.StatusCreated, response.Code, response.Body.String())

	var bindingResponse postgresapi.CreateSessionBindingResponse
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &bindingResponse))
	fingerprint := sha256.Sum256(clientCertificate.Raw)
	expectedBindingID := postgresidentity.BindingIDFromFingerprint(fingerprint[:])
	require.Equal(t, expectedBindingID, bindingResponse.BindingID)

	record, err := client.Get(t.Context(), &databroker.GetRequest{
		Type: grpcutil.GetTypeURL(new(sessionpb.SessionBinding)),
		Id:   expectedBindingID,
	})
	require.NoError(t, err)
	require.NotNil(t, record.GetRecord())
	require.Nil(t, record.GetRecord().GetDeletedAt())
	var binding sessionpb.SessionBinding
	require.NoError(t, record.GetRecord().GetData().UnmarshalTo(&binding))
	require.Equal(t, sessionpb.ProtocolPostgres, binding.GetProtocol())
	require.Equal(t, webSession.Id, binding.GetSessionId())
	require.Equal(t, webSession.UserId, binding.GetUserId())
	require.Equal(t, "db.example.com", binding.GetDetails()[postgresidentity.DetailRouteHostname])
	require.WithinDuration(t, binding.GetExpiresAt().AsTime(), bindingResponse.ExpiresAt, time.Millisecond)
	return expectedBindingID
}

func seedPostgresRouteTestSession(t *testing.T, client databroker.DataBrokerServiceClient, certs postgresRouteTestCerts) {
	t.Helper()

	sum := sha256.Sum256(certs.clientCert.Certificate[0])
	bindingID := postgresidentity.BindingIDFromFingerprint(sum[:])
	require.NotEmpty(t, bindingID)

	now := time.Now()
	session := &sessionpb.Session{
		Id:        "POSTGRES-SESSION-1",
		UserId:    "POSTGRES-USER-1",
		IdpId:     postgresRouteTestIdentityProviderID(t, certs),
		IssuedAt:  timestamppb.New(now.Add(-time.Minute)),
		ExpiresAt: timestamppb.New(now.Add(time.Hour)),
	}
	user := &userpb.User{
		Id:    "POSTGRES-USER-1",
		Email: "alice@example.com",
	}
	binding := &sessionpb.SessionBinding{
		Protocol:  sessionpb.ProtocolPostgres,
		SessionId: session.Id,
		UserId:    session.UserId,
		IssuedAt:  timestamppb.New(now.Add(-time.Minute)),
		ExpiresAt: timestamppb.New(now.Add(time.Hour)),
		Details: map[string]string{
			postgresidentity.DetailRouteHostname: "db.example.com",
		},
	}
	_, err := client.Put(t.Context(), &databroker.PutRequest{Records: []*databroker.Record{
		databroker.NewRecord(session),
		databroker.NewRecord(user),
		{
			Type: grpcutil.GetTypeURL(new(sessionpb.SessionBinding)),
			Id:   bindingID,
			Data: protoutil.NewAny(binding),
		},
	}})
	require.NoError(t, err)
}

func putPostgresRouteTestSessionBinding(
	t *testing.T,
	client databroker.DataBrokerServiceClient,
	certs postgresRouteTestCerts,
	mutate func(*sessionpb.SessionBinding, *sessionpb.Session, *databroker.Record, *databroker.Record),
) string {
	t.Helper()

	sum := sha256.Sum256(certs.clientCert.Certificate[0])
	bindingID := postgresidentity.BindingIDFromFingerprint(sum[:])
	require.NotEmpty(t, bindingID)

	now := time.Now()
	webSession := &sessionpb.Session{
		Id:        "POSTGRES-SESSION-1",
		UserId:    "POSTGRES-USER-1",
		IdpId:     postgresRouteTestIdentityProviderID(t, certs),
		IssuedAt:  timestamppb.New(now.Add(-time.Minute)),
		ExpiresAt: timestamppb.New(now.Add(time.Hour)),
	}
	binding := &sessionpb.SessionBinding{
		Protocol:  sessionpb.ProtocolPostgres,
		SessionId: webSession.Id,
		UserId:    webSession.UserId,
		IssuedAt:  timestamppb.New(now.Add(-time.Minute)),
		ExpiresAt: timestamppb.New(now.Add(time.Hour)),
		Details: map[string]string{
			postgresidentity.DetailRouteHostname: "db.example.com",
		},
	}
	sessionRecord := databroker.NewRecord(webSession)
	bindingRecord := &databroker.Record{
		Type: grpcutil.GetTypeURL(new(sessionpb.SessionBinding)),
		Id:   bindingID,
		Data: protoutil.NewAny(binding),
	}
	if mutate != nil {
		mutate(binding, webSession, bindingRecord, sessionRecord)
		bindingRecord.Data = protoutil.NewAny(binding)
		sessionRecord.Data = protoutil.NewAny(webSession)
	}
	_, err := client.Put(t.Context(), &databroker.PutRequest{Records: []*databroker.Record{
		sessionRecord,
		{
			Type: grpcutil.GetTypeURL(new(userpb.User)),
			Id:   webSession.UserId,
			Data: protoutil.NewAny(&userpb.User{
				Id:    webSession.UserId,
				Email: "alice@example.com",
			}),
		},
		bindingRecord,
	}})
	require.NoError(t, err)
	return bindingID
}

func newPostgresRouteTestAuthorize(t *testing.T, db databroker.DataBrokerServiceClient) *authorize.Authorize {
	t.Helper()

	opts := config.NewDefaultOptions()
	opts.SharedKey = cryptutil.NewBase64Key()
	opts.RuntimeFlags[config.RuntimeFlagAuthorizeUseSyncedData] = false
	authz, err := authorize.New(t.Context(), config.New(opts), authorize.WithDataBrokerServiceClient(db))
	require.NoError(t, err)
	return authz
}

func TestPostgresRuntimeRejectsUnsupportedDownstreamClientCA(t *testing.T) {
	cfg := newPostgresRouteTestConfig(postgresRouteTestCerts{})
	cfg.Options.Routes[0].TLSDownstreamClientCA = base64.StdEncoding.EncodeToString([]byte("unused-postgres-client-ca"))
	authority, sharedKey, err := postgresManagedPostgresAuthority(cfg)
	require.NoError(t, err)

	_, err = newPostgresRuntimeSnapshot(cfg, authority, sharedKey)
	require.ErrorContains(t, err, "postgres routes do not support tls_downstream_client_ca")
}

func newPostgresRouteTestConfig(_ postgresRouteTestCerts) *config.Config {
	opts := config.NewDefaultOptions()
	opts.InstallationID = "POSTGRES-INSTALLATION-1"
	opts.SharedKey = base64.StdEncoding.EncodeToString([]byte("01234567890123456789012345678901"))
	route := managedPostgresTestPolicy(configpb.PostgresUpstreamTLSMode_POSTGRES_UPSTREAM_TLS_MODE_UNSPECIFIED)
	route.From = "postgres://db.example.com"
	route.To = config.WeightedURLs{{URL: url.URL{Scheme: "postgres", Host: "postgres.internal:5432"}}}
	opts.Routes = []config.Policy{route}
	return config.New(opts)
}

func postgresRouteTestIdentityProviderID(t testing.TB, certs postgresRouteTestCerts) string {
	t.Helper()
	cfg := newPostgresRouteTestConfig(certs)
	idp, err := cfg.Options.GetIdentityProviderForPolicy(&cfg.Options.Routes[0])
	require.NoError(t, err)
	require.NotEmpty(t, idp.GetId())
	return idp.GetId()
}

func newPostgresCoreAdapterRuntime(cfg *config.Config) *atomic.Pointer[postgresRuntimeSnapshot] {
	if cfg.Options.InstallationID == "" {
		cfg.Options.InstallationID = "POSTGRES-INSTALLATION-1"
	}
	if cfg.Options.SharedKey == "" && cfg.Options.SharedSecretFile == "" {
		cfg.Options.SharedKey = base64.StdEncoding.EncodeToString([]byte("01234567890123456789012345678901"))
	}
	authority, sharedKey, err := postgresManagedPostgresAuthority(cfg)
	if err != nil {
		panic(err)
	}
	snapshot, err := newPostgresRuntimeSnapshot(cfg, authority, sharedKey)
	if err != nil {
		panic(err)
	}
	runtime := new(atomic.Pointer[postgresRuntimeSnapshot])
	runtime.Store(snapshot)
	return runtime
}

func managedPostgresTestPolicy(tlsMode configpb.PostgresUpstreamTLSMode) config.Policy {
	return config.Policy{
		RouteOptions: config.RouteOptions{
			Postgres: nullable.From(config.PostgresRouteSettings{
				AuthenticationMode: nullable.From(configpb.PostgresAuthenticationMode_POSTGRES_AUTHENTICATION_MODE_MANAGED),
				Username:           nullable.From("pomeriumtest"),
				Database:           nullable.From("pomeriumtest"),
				Password:           nullable.From("pomeriumtest"),
				UpstreamTlsMode:    nullable.From(tlsMode),
			}),
		},
	}
}

type fakeManagedPostgresVerifier struct {
	expiresAt time.Time
	err       error
	calls     atomic.Int32
}

func (v *fakeManagedPostgresVerifier) VerifyManagedPostgres(context.Context, capability.ManagedPostgresAuthority) (time.Time, error) {
	v.calls.Add(1)
	return v.expiresAt, v.err
}

func postgresRouteTestAuthRequest(certs postgresRouteTestCerts) postgresproxy.AuthRequest {
	sum := sha256.Sum256(certs.clientCert.Certificate[0])
	return postgresproxy.AuthRequest{
		ClientAddr:       &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 54321},
		ServerName:       "db.example.com",
		ClientCertSHA256: hex.EncodeToString(sum[:]),
		ClientCertPEM: string(pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certs.clientCert.Certificate[0],
		})),
		Database: "pomeriumtest",
		Username: "alice",
	}
}

func startPostgresRouteTestPostgres(t *testing.T) string {
	t.Helper()

	ctx := t.Context()
	req := testcontainers.ContainerRequest{
		Image:        "postgres:16",
		ExposedPorts: []string{"5432/tcp"},
		Env: map[string]string{
			"POSTGRES_DB":          "pomeriumtest",
			"POSTGRES_PASSWORD":    "pomeriumtest",
			"POSTGRES_USER":        "pomeriumtest",
			"POSTGRES_INITDB_ARGS": "--auth-host=password",
		},
		WaitingFor: wait.ForListeningPort("5432/tcp"),
	}
	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, testcontainers.TerminateContainer(container))
	})

	host, err := container.Host(ctx)
	require.NoError(t, err)
	if host == "localhost" {
		host = "127.0.0.1"
	}
	port, err := container.MappedPort(ctx, "5432/tcp")
	require.NoError(t, err)
	addr := net.JoinHostPort(host, port.Port())
	waitForPostgresRouteTestPostgres(t, addr)
	return addr
}

func waitForPostgresRouteTestPostgres(t *testing.T, addr string) {
	t.Helper()

	deadline := time.Now().Add(30 * time.Second)
	dsn := fmt.Sprintf("postgres://pomeriumtest:pomeriumtest@%s/pomeriumtest?sslmode=disable", addr)
	var lastErr error
	for time.Now().Before(deadline) {
		conn, err := pgx.Connect(context.Background(), dsn)
		if err == nil {
			conn.Close(context.Background())
			return
		}
		lastErr = err
		time.Sleep(100 * time.Millisecond)
	}
	require.NoError(t, lastErr)
}

func execPostgresRouteTestUpstream(t *testing.T, addr string, sql string) {
	t.Helper()

	conn := connectPostgresRouteTestUpstream(t, addr)
	defer conn.Close(context.Background())
	_, err := conn.Exec(context.Background(), sql)
	require.NoError(t, err)
}

func runPostgresRouteTestPSQL(t *testing.T, addr string, certs postgresRouteTestCerts) {
	t.Helper()

	_, portString, err := net.SplitHostPort(addr)
	require.NoError(t, err)
	port, err := strconv.Atoi(portString)
	require.NoError(t, err)

	connInfo := fmt.Sprintf(
		"host=db.example.com port=%d user=alice dbname=pomeriumtest application_name=postgres-route-psql-test sslmode=verify-full sslrootcert=/certs/ca.pem sslcert=/certs/client.pem sslkey=/certs/client-key.pem gssencmode=disable",
		port,
	)
	script := fmt.Sprintf(`
set -eu
conn=%q
hostaddr=$(getent hosts host.docker.internal | awk 'NR == 1 {print $1}')
test -n "$hostaddr"
conn="$conn hostaddr=$hostaddr"
psql -v ON_ERROR_STOP=1 -At -d "$conn" -c "select current_user || '|' || current_database()" | tee /tmp/allow.out
grep -qx "pomeriumtest|pomeriumtest" /tmp/allow.out
`, connInfo)

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	container, err := testcontainers.Run(ctx, "postgres:16",
		testcontainers.WithEntrypoint("sh", "-c"),
		testcontainers.WithCmd(script),
		testcontainers.WithFiles(
			testcontainers.ContainerFile{HostFilePath: certs.caPath, ContainerFilePath: "/certs/ca.pem", FileMode: 0o600},
			testcontainers.ContainerFile{HostFilePath: certs.clientCertPath, ContainerFilePath: "/certs/client.pem", FileMode: 0o600},
			testcontainers.ContainerFile{HostFilePath: certs.clientKeyPath, ContainerFilePath: "/certs/client-key.pem", FileMode: 0o600},
		),
		testcontainers.WithHostConfigModifier(func(hostConfig *dockercontainer.HostConfig) {
			hostConfig.ExtraHosts = append(hostConfig.ExtraHosts, "host.docker.internal:host-gateway")
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

func requirePostgresRouteTestTableExists(t *testing.T, addr string, table string) {
	t.Helper()

	conn := connectPostgresRouteTestUpstream(t, addr)
	defer conn.Close(context.Background())
	var exists bool
	err := conn.QueryRow(context.Background(), "select to_regclass($1) is not null", table).Scan(&exists)
	require.NoError(t, err)
	require.True(t, exists, "expected upstream table %q to exist", table)
}

func requirePostgresRouteTestTableMissing(t *testing.T, addr string, table string) {
	t.Helper()

	conn := connectPostgresRouteTestUpstream(t, addr)
	defer conn.Close(context.Background())
	var exists bool
	err := conn.QueryRow(context.Background(), "select to_regclass($1) is not null", table).Scan(&exists)
	require.NoError(t, err)
	require.False(t, exists, "expected upstream table %q to be absent", table)
}

func connectPostgresRouteTestUpstream(t *testing.T, addr string) *pgx.Conn {
	t.Helper()

	dsn := fmt.Sprintf("postgres://pomeriumtest:pomeriumtest@%s/pomeriumtest?sslmode=disable", addr)
	conn, err := pgx.Connect(context.Background(), dsn)
	require.NoError(t, err)
	return conn
}

func connectPostgresRouteTestPGX(t *testing.T, addr string, certs postgresRouteTestCerts, user string, mode pgx.QueryExecMode) *pgx.Conn {
	t.Helper()

	conn, err := connectPostgresRouteTestPGXErr(t, addr, certs, user, mode)
	require.NoError(t, err)
	return conn
}

func connectPostgresRouteTestPGXErr(t *testing.T, addr string, certs postgresRouteTestCerts, user string, mode pgx.QueryExecMode) (*pgx.Conn, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	return connectPostgresRouteTestPGXErrContext(ctx, t, addr, certs, user, mode)
}

func connectPostgresRouteTestPGXErrContext(
	ctx context.Context,
	t *testing.T,
	addr string,
	certs postgresRouteTestCerts,
	user string,
	mode pgx.QueryExecMode,
) (*pgx.Conn, error) {
	t.Helper()

	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	dsn := fmt.Sprintf(
		"host=%s port=%s user=%s dbname=pomeriumtest application_name=postgres-route-test sslmode=verify-full sslrootcert=%s sslcert=%s sslkey=%s gssencmode=disable",
		host, port, user, certs.caPath, certs.clientCertPath, certs.clientKeyPath,
	)
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}
	cfg.DefaultQueryExecMode = mode
	if cfg.TLSConfig != nil {
		cfg.TLSConfig.ServerName = "db.example.com"
	}
	return pgx.ConnectConfig(ctx, cfg)
}

func postgresRouteTestPPL(t *testing.T, ppl string) *config.PPLPolicy {
	t.Helper()

	p, err := policyparser.New().ParseYAML(strings.NewReader(ppl))
	require.NoError(t, err)
	return &config.PPLPolicy{Policy: p}
}

func mustParseURL(t testing.TB, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	require.NoError(t, err)
	return u
}

type postgresRouteTestCerts struct {
	caPEM          []byte
	caPath         string
	serverCertPEM  []byte
	serverKeyPEM   []byte
	clientCert     tls.Certificate
	clientCertPath string
	clientKeyPath  string
}

func newPostgresRouteTestCerts(t *testing.T) postgresRouteTestCerts {
	t.Helper()

	dir := t.TempDir()
	ca := newPostgresRouteTestCA(t, "postgres-route-test-ca")
	caPath := filepath.Join(dir, "ca.pem")
	require.NoError(t, os.WriteFile(caPath, ca.certPEM, 0o600))

	serverCert := issuePostgresRouteTestCert(t, ca.cert, ca.key, "db.example.com", []string{"db.example.com"}, x509.ExtKeyUsageServerAuth)
	clientCert := issuePostgresRouteTestClientCert(t, "db.example.com")
	clientTLS, err := tls.X509KeyPair(clientCert.certPEM, clientCert.keyPEM)
	require.NoError(t, err)

	clientCertPath := filepath.Join(dir, "client.pem")
	clientKeyPath := filepath.Join(dir, "client-key.pem")
	require.NoError(t, os.WriteFile(clientCertPath, clientCert.certPEM, 0o600))
	require.NoError(t, os.WriteFile(clientKeyPath, clientCert.keyPEM, 0o600))

	return postgresRouteTestCerts{
		caPEM:          ca.certPEM,
		caPath:         caPath,
		serverCertPEM:  serverCert.certPEM,
		serverKeyPEM:   serverCert.keyPEM,
		clientCert:     clientTLS,
		clientCertPath: clientCertPath,
		clientKeyPath:  clientKeyPath,
	}
}

func rotatePostgresRouteTestServerCertificate(
	t *testing.T,
	current postgresRouteTestCerts,
) postgresRouteTestCerts {
	t.Helper()

	dir := t.TempDir()
	ca := newPostgresRouteTestCA(t, "postgres-route-test-rotated-ca")
	caPath := filepath.Join(dir, "ca.pem")
	require.NoError(t, os.WriteFile(caPath, ca.certPEM, 0o600))
	serverCert := issuePostgresRouteTestCert(
		t, ca.cert, ca.key, "db.example.com", []string{"db.example.com"}, x509.ExtKeyUsageServerAuth)
	current.caPEM = ca.certPEM
	current.caPath = caPath
	current.serverCertPEM = serverCert.certPEM
	current.serverKeyPEM = serverCert.keyPEM
	return current
}

type postgresRouteTestCA struct {
	cert    *x509.Certificate
	key     *rsa.PrivateKey
	certPEM []byte
}

func newPostgresRouteTestCA(t *testing.T, cn string) postgresRouteTestCA {
	t.Helper()

	key := mustPostgresRouteTestRSAKey(t)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return postgresRouteTestCA{
		cert:    cert,
		key:     key,
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
	}
}

func issuePostgresRouteTestCA(t *testing.T, parent postgresRouteTestCA, cn string) postgresRouteTestCA {
	t.Helper()

	key := mustPostgresRouteTestRSAKey(t)
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent.cert, &key.PublicKey, parent.key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return postgresRouteTestCA{
		cert:    cert,
		key:     key,
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
	}
}

type postgresRouteTestIssuedCert struct {
	certPEM []byte
	keyPEM  []byte
}

func issuePostgresRouteTestCert(t *testing.T, ca *x509.Certificate, caKey *rsa.PrivateKey, cn string, dnsNames []string, usage x509.ExtKeyUsage) postgresRouteTestIssuedCert {
	t.Helper()

	key := mustPostgresRouteTestRSAKey(t)
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{usage},
		DNSNames:     dnsNames,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	require.NoError(t, err)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return postgresRouteTestIssuedCert{certPEM: certPEM, keyPEM: keyPEM}
}

func issuePostgresRouteTestClientCert(t *testing.T, hostname string) postgresRouteTestIssuedCert {
	t.Helper()

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "pomerium-postgres-client"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{hostname},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, publicKey, privateKey)
	require.NoError(t, err)
	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	require.NoError(t, err)
	return postgresRouteTestIssuedCert{
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		keyPEM:  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
	}
}

func mustPostgresRouteTestRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return key
}
