package pomerium

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	dockercontainer "github.com/moby/moby/api/types/container"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/authorize"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/postgresproxy"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	"github.com/pomerium/pomerium/pkg/databrokerutil/testutil"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	sessionpb "github.com/pomerium/pomerium/pkg/grpc/session"
	userpb "github.com/pomerium/pomerium/pkg/grpc/user"
	"github.com/pomerium/pomerium/pkg/grpcutil"
	policyparser "github.com/pomerium/pomerium/pkg/policy/parser"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

func TestShouldStartPostgres(t *testing.T) {
	opts := config.NewDefaultOptions()
	require.False(t, shouldStartPostgres(opts))

	opts.PostgresAddr = "127.0.0.1:15432"
	require.False(t, shouldStartPostgres(opts))

	opts.RuntimeFlags[config.RuntimeFlagPostgres] = true
	require.True(t, shouldStartPostgres(opts))
}

func TestPostgresListenerStopsWhenDisabledByConfig(t *testing.T) {
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

	next := newPostgresRouteTestConfig(certs)
	next.Options.SharedKey = cfg.Options.SharedKey
	next.Options.PostgresAddr = cfg.Options.PostgresAddr
	next.Options.Cert = cfg.Options.Cert
	next.Options.Key = cfg.Options.Key
	src.SetConfig(ctx, next)

	select {
	case err := <-runDone:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("postgres listener did not stop after postgres runtime flag was disabled")
	}
}

func TestPostgresSessionBindingIDFromFingerprint(t *testing.T) {
	sum := sha256.Sum256([]byte("client-cert"))
	got, err := postgresSessionBindingIDFromFingerprint(sum[:])
	require.NoError(t, err)
	require.Equal(t, "postgrescert-SHA256:"+base64.RawStdEncoding.EncodeToString(sum[:]), got)

	_, err = postgresSessionBindingIDFromFingerprint([]byte("short"))
	require.Error(t, err)
}

func TestPostgresRequestFromSessionUsesSourceIP(t *testing.T) {
	req := postgresRequestFromSession(&postgresproxy.Session{
		ClientAddr: "[2001:db8::1]:54321",
	}, "SELECT", "simple")
	require.Equal(t, "2001:db8::1", req.SourceAddress)

	req = postgresRequestFromSession(&postgresproxy.Session{
		ClientAddr: "127.0.0.1:54321",
	}, "SELECT", "simple")
	require.Equal(t, "127.0.0.1", req.SourceAddress)

	req = postgresRequestFromSession(&postgresproxy.Session{
		ClientAddr: "not-a-host-port",
	}, "SELECT", "simple")
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
					Path:   "/appdb",
					User:   url.UserPassword("dbuser", "secret"),
				},
			}},
			TLSUpstreamServerName: "postgres.example.internal",
		},
	}
	routeID, err := cfg.Options.Routes[0].RouteID()
	require.NoError(t, err)

	var current atomic.Pointer[config.Config]
	current.Store(cfg)
	adapter := &postgresCoreAdapter{current: &current}
	session := &postgresproxy.Session{
		Hostname:     "db.example.com",
		RouteID:      routeID,
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

func TestPostgresCoreAdapterAuthorizationErrorsFailClosed(t *testing.T) {
	certs := newPostgresRouteTestCerts(t)
	db := testutil.NewTestDatabroker(t)
	seedPostgresRouteTestSession(t, db, certs)
	cfg := newPostgresRouteTestConfig(certs)
	authz, err := authorize.New(t.Context(), cfg, authorize.WithDataBrokerServiceClient(db))
	require.NoError(t, err)

	var current atomic.Pointer[config.Config]
	current.Store(cfg)
	adapter := &postgresCoreAdapter{current: &current, authz: authz}
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

	decision, err := adapter.AuthorizeQuery(ctx, postgresproxy.QueryRequest{
		Session:        session,
		Protocol:       postgresproxy.QueryProtocolSimple,
		StatementClass: "SELECT",
	})
	require.Error(t, err)
	require.Nil(t, decision)
}

func TestPostgresUpstreamTLSConfig(t *testing.T) {
	t.Parallel()

	opts := config.NewDefaultOptions()
	t.Run("defaults to verified TLS", func(t *testing.T) {
		upstream := mustParseURL(t, "postgres://dbuser:secret@postgres.internal:5432")
		tlsConfig, err := postgresUpstreamTLSConfig(opts, &config.Policy{}, upstream)
		require.NoError(t, err)
		require.NotNil(t, tlsConfig)
		require.Equal(t, "postgres.internal", tlsConfig.ServerName)
		require.False(t, tlsConfig.InsecureSkipVerify)
	})
	t.Run("explicit plaintext", func(t *testing.T) {
		upstream := mustParseURL(t, "postgres://dbuser:secret@postgres.internal:5432?sslmode=disable")
		tlsConfig, err := postgresUpstreamTLSConfig(opts, &config.Policy{}, upstream)
		require.NoError(t, err)
		require.Nil(t, tlsConfig)
	})
	t.Run("require skips verification", func(t *testing.T) {
		upstream := mustParseURL(t, "postgres://dbuser:secret@postgres.internal:5432?sslmode=require")
		tlsConfig, err := postgresUpstreamTLSConfig(opts, &config.Policy{}, upstream)
		require.NoError(t, err)
		require.NotNil(t, tlsConfig)
		require.True(t, tlsConfig.InsecureSkipVerify)
	})
}

func TestVerifyPostgresClientCertificateForRoute(t *testing.T) {
	trusted := newPostgresRouteTestCerts(t)
	untrusted := newPostgresRouteTestCerts(t)
	clientPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: trusted.clientCert.Certificate[0],
	}))

	opts := config.NewDefaultOptions()
	opts.DownstreamMTLS.CA = base64.StdEncoding.EncodeToString(trusted.caPEM)
	require.NoError(t, verifyPostgresClientCertificateForRoute(opts, &config.Policy{}, clientPEM, time.Now()))

	route := &config.Policy{
		TLSDownstreamClientCA: base64.StdEncoding.EncodeToString(trusted.caPEM),
	}
	require.NoError(t, verifyPostgresClientCertificateForRoute(config.NewDefaultOptions(), route, clientPEM, time.Now()))

	route.TLSDownstreamClientCA = base64.StdEncoding.EncodeToString(untrusted.caPEM)
	require.Error(t, verifyPostgresClientCertificateForRoute(config.NewDefaultOptions(), route, clientPEM, time.Now()))

	root := newPostgresRouteTestCA(t, "postgres-route-root-ca")
	intermediate := issuePostgresRouteTestCA(t, root, "postgres-route-intermediate-ca")
	client := issuePostgresRouteTestCert(t, intermediate.cert, intermediate.key, "alice", nil, x509.ExtKeyUsageClientAuth)
	chainPEM := string(append(client.certPEM, intermediate.certPEM...))
	opts.DownstreamMTLS.CA = base64.StdEncoding.EncodeToString(root.certPEM)
	require.Error(t, verifyPostgresClientCertificateForRoute(opts, &config.Policy{}, string(client.certPEM), time.Now()))
	require.NoError(t, verifyPostgresClientCertificateForRoute(opts, &config.Policy{}, chainPEM, time.Now()))
}

func TestPostgresCoreRouteAuthorizeAllowAndDeny(t *testing.T) {
	testcontainers.SkipIfProviderIsNotHealthy(t)

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	upstreamAddr := startPostgresRouteTestPostgres(t)
	execPostgresRouteTestUpstream(t, upstreamAddr, "create table route_guard (id int)")
	certs := newPostgresRouteTestCerts(t)
	db := testutil.NewTestDatabroker(t)
	seedPostgresRouteTestSession(t, db, certs)

	opts := config.NewDefaultOptions()
	opts.SharedKey = cryptutil.NewBase64Key()
	opts.PostgresAddr = "0.0.0.0:0"
	opts.RuntimeFlags[config.RuntimeFlagPostgres] = true
	opts.RuntimeFlags[config.RuntimeFlagAuthorizeUseSyncedData] = false
	opts.Cert = base64.StdEncoding.EncodeToString(certs.serverCertPEM)
	opts.Key = base64.StdEncoding.EncodeToString(certs.serverKeyPEM)
	opts.DownstreamMTLS.CA = base64.StdEncoding.EncodeToString(certs.caPEM)
	opts.Routes = []config.Policy{{
		From: "postgres://db.example.com",
		To: config.WeightedURLs{{
			URL: url.URL{
				Scheme:   "postgres",
				Host:     upstreamAddr,
				Path:     "/pomeriumtest",
				User:     url.UserPassword("pomeriumtest", "pomeriumtest"),
				RawQuery: "sslmode=disable",
			},
		}},
		Policy: postgresRouteTestPPL(t, `
- allow:
    and:
      - postgres_database:
          is: pomeriumtest
      - postgres_username:
          is: alice
- deny:
    and:
      - postgres_statement_class:
          is: DROP
`),
	}}

	cfg := config.New(opts)
	authz, err := authorize.New(ctx, cfg, authorize.WithDataBrokerServiceClient(db))
	require.NoError(t, err)
	svc, err := setupPostgres(ctx, config.NewStaticSource(cfg), authz)
	require.NoError(t, err)
	require.NotNil(t, svc)

	runDone := make(chan error, 1)
	go func() {
		runDone <- svc.Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		_ = svc.listener.Close()
		select {
		case err := <-runDone:
			require.NoError(t, err)
		case <-time.After(5 * time.Second):
			t.Fatal("postgres listener did not stop")
		}
	})

	_, proxyPort, err := net.SplitHostPort(svc.listener.Addr().String())
	require.NoError(t, err)
	proxyAddr := net.JoinHostPort("127.0.0.1", proxyPort)
	conn := connectPostgresRouteTestPGX(t, proxyAddr, certs, "alice", pgx.QueryExecModeSimpleProtocol)
	defer conn.Close(context.Background())

	var currentUser string
	require.NoError(t, conn.QueryRow(ctx, "select current_user").Scan(&currentUser))
	require.Equal(t, "pomeriumtest", currentUser)

	_, err = conn.Exec(ctx, "drop table route_guard")
	require.Error(t, err)
	require.Contains(t, strings.ToLower(err.Error()), "postgres query denied")
	requirePostgresRouteTestTableExists(t, upstreamAddr, "route_guard")

	runPostgresRouteTestPSQL(t, proxyAddr, certs)
	requirePostgresRouteTestTableExists(t, upstreamAddr, "route_guard")

	blocked, err := connectPostgresRouteTestPGXErr(t, proxyAddr, certs, "blocked", pgx.QueryExecModeSimpleProtocol)
	if blocked != nil {
		defer blocked.Close(context.Background())
	}
	require.Error(t, err)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		require.Equal(t, "42501", pgErr.Code)
	} else {
		require.Contains(t, strings.ToLower(err.Error()), "postgres session denied")
	}
}

func TestPostgresCoreAdapterRejectsInvalidSessionBindings(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*sessionpb.SessionBinding, *sessionpb.Session, *databroker.Record, *databroker.Record)
		wantErr string
	}{
		{
			name: "wrong protocol",
			mutate: func(binding *sessionpb.SessionBinding, _ *sessionpb.Session, _, _ *databroker.Record) {
				binding.Protocol = sessionpb.ProtocolSSH
			},
			wantErr: "invalid protocol",
		},
		{
			name: "expired binding",
			mutate: func(binding *sessionpb.SessionBinding, _ *sessionpb.Session, _, _ *databroker.Record) {
				binding.ExpiresAt = timestamppb.New(time.Now().Add(-time.Minute))
			},
			wantErr: "expired",
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
			wantErr: "web session expired",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			certs := newPostgresRouteTestCerts(t)
			db := testutil.NewTestDatabroker(t)
			bindingID := putPostgresRouteTestSessionBinding(t, db, certs, tc.mutate)
			authz := newPostgresRouteTestAuthorize(t, db)
			var current atomic.Pointer[config.Config]
			current.Store(newPostgresRouteTestConfig(certs))
			adapter := &postgresCoreAdapter{current: &current, authz: authz}

			_, _, _, err := adapter.resolveSessionBinding(t.Context(), bindingID)
			if tc.name == "expired web session" {
				_, err = adapter.Authenticate(t.Context(), postgresRouteTestAuthRequest(certs))
			}
			require.Error(t, err)
			require.Contains(t, err.Error(), tc.wantErr)
		})
	}
}

func TestPostgresCoreAdapterReauthorizeRejectsBindingUserMismatch(t *testing.T) {
	certs := newPostgresRouteTestCerts(t)
	db := testutil.NewTestDatabroker(t)
	bindingID := putPostgresRouteTestSessionBinding(t, db, certs, func(binding *sessionpb.SessionBinding, _ *sessionpb.Session, _, _ *databroker.Record) {
		binding.UserId = "POSTGRES-USER-OTHER"
	})
	authz := newPostgresRouteTestAuthorize(t, db)
	cfg := newPostgresRouteTestConfig(certs)
	routeID, err := cfg.Options.Routes[0].RouteID()
	require.NoError(t, err)
	var current atomic.Pointer[config.Config]
	current.Store(cfg)
	adapter := &postgresCoreAdapter{current: &current, authz: authz}

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

func seedPostgresRouteTestSession(t *testing.T, client databroker.DataBrokerServiceClient, certs postgresRouteTestCerts) {
	t.Helper()

	sum := sha256.Sum256(certs.clientCert.Certificate[0])
	bindingID, err := postgresSessionBindingIDFromFingerprint(sum[:])
	require.NoError(t, err)

	now := time.Now()
	session := &sessionpb.Session{
		Id:        "POSTGRES-SESSION-1",
		UserId:    "POSTGRES-USER-1",
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
	}
	_, err = client.Put(t.Context(), &databroker.PutRequest{Records: []*databroker.Record{
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
	bindingID, err := postgresSessionBindingIDFromFingerprint(sum[:])
	require.NoError(t, err)

	now := time.Now()
	webSession := &sessionpb.Session{
		Id:        "POSTGRES-SESSION-1",
		UserId:    "POSTGRES-USER-1",
		IssuedAt:  timestamppb.New(now.Add(-time.Minute)),
		ExpiresAt: timestamppb.New(now.Add(time.Hour)),
	}
	binding := &sessionpb.SessionBinding{
		Protocol:  sessionpb.ProtocolPostgres,
		SessionId: webSession.Id,
		UserId:    webSession.UserId,
		IssuedAt:  timestamppb.New(now.Add(-time.Minute)),
		ExpiresAt: timestamppb.New(now.Add(time.Hour)),
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
	_, err = client.Put(t.Context(), &databroker.PutRequest{Records: []*databroker.Record{
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

func newPostgresRouteTestConfig(certs postgresRouteTestCerts) *config.Config {
	opts := config.NewDefaultOptions()
	opts.DownstreamMTLS.CA = base64.StdEncoding.EncodeToString(certs.caPEM)
	opts.Routes = []config.Policy{{
		From: "postgres://db.example.com",
		To: config.WeightedURLs{{
			URL: url.URL{
				Scheme:   "postgres",
				Host:     "postgres.internal:5432",
				Path:     "/pomeriumtest",
				User:     url.UserPassword("pomeriumtest", "pomeriumtest"),
				RawQuery: "sslmode=disable",
			},
		}},
	}}
	return config.New(opts)
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
if psql -v ON_ERROR_STOP=1 -At -d "$conn" -c "drop table route_guard" >/tmp/deny.out 2>&1; then
	cat /tmp/deny.out
	exit 1
fi
cat /tmp/deny.out
grep -qi "postgres query denied" /tmp/deny.out
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
	require.Contains(t, strings.ToLower(string(output)), "postgres query denied")
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
	return pgx.ConnectConfig(context.Background(), cfg)
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
	clientCert := issuePostgresRouteTestCert(t, ca.cert, ca.key, "alice", nil, x509.ExtKeyUsageClientAuth)
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

func mustPostgresRouteTestRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return key
}
