package postgresproxy

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	oteltrace "go.opentelemetry.io/otel/trace"

	"github.com/pomerium/pomerium/pkg/telemetry/trace"
)

func TestProxySimpleQueryDenyAndRecord(t *testing.T) {
	upstreamAddr := startPasswordPostgres(t)
	certs := newTestCerts(t)
	rec := &memoryRecorder{}
	policy := &fakePolicy{
		query: func(_ context.Context, req QueryRequest) (*Decision, error) {
			if req.StatementClass == "DROP" {
				return &Decision{Action: DecisionDeny, Reason: "DROP is not allowed"}, nil
			}
			return &Decision{Action: DecisionAllow}, nil
		},
	}
	proxyAddr, stop := startProxy(t, upstreamAddr, certs, policy, rec, nil)
	defer stop()

	conn := connectPGX(t, proxyAddr, certs, pgx.QueryExecModeSimpleProtocol)
	defer conn.Close(context.Background())

	var n int
	require.NoError(t, conn.QueryRow(context.Background(), "select 41 + 1").Scan(&n))
	require.Equal(t, 42, n)

	_, err := conn.Exec(context.Background(), "drop table if exists blocked_target")
	require.Error(t, err)
	require.Contains(t, strings.ToLower(err.Error()), "postgres query denied")

	records := rec.records()
	require.Len(t, records, 2)
	require.Equal(t, "SELECT", records[0].StatementClass)
	require.Equal(t, DecisionAllow, records[0].Decision)
	require.Equal(t, "ok", records[0].Status)
	require.Equal(t, "DROP", records[1].StatementClass)
	require.Equal(t, DecisionDeny, records[1].Decision)
	require.Equal(t, "denied", records[1].Status)
}

func TestProxyRejectsMultiStatementSimpleQuery(t *testing.T) {
	upstreamAddr := startPasswordPostgres(t)
	certs := newTestCerts(t)
	rec := &memoryRecorder{}
	proxyAddr, stop := startProxy(t, upstreamAddr, certs, &fakePolicy{}, rec, nil)
	defer stop()

	conn := connectPGX(t, proxyAddr, certs, pgx.QueryExecModeSimpleProtocol)
	defer conn.Close(context.Background())

	_, err := conn.Exec(context.Background(), "select 1; select 2")
	require.Error(t, err)

	records := rec.records()
	require.Len(t, records, 1)
	require.Equal(t, "MULTI", records[0].StatementClass)
	require.Equal(t, DecisionDeny, records[0].Decision)
	require.Contains(t, records[0].Reason, "multi-statement")
}

func TestProxyNestedBlockCommentBypassSimpleDenied(t *testing.T) {
	upstreamAddr := startPasswordPostgres(t)
	execUpstream(t, upstreamAddr, "create table users (id int)")
	certs := newTestCerts(t)
	rec := &memoryRecorder{}
	policy := &fakePolicy{
		query: func(_ context.Context, req QueryRequest) (*Decision, error) {
			if req.StatementClass == "DROP" {
				return &Decision{Action: DecisionDeny, Reason: "DROP is not allowed"}, nil
			}
			return &Decision{Action: DecisionAllow}, nil
		},
	}
	proxyAddr, stop := startProxy(t, upstreamAddr, certs, policy, rec, nil)
	defer stop()

	conn := connectPGX(t, proxyAddr, certs, pgx.QueryExecModeSimpleProtocol)
	defer conn.Close(context.Background())

	_, err := conn.Exec(context.Background(), "/*/* */ SELECT */ DROP TABLE users")
	require.Error(t, err)
	require.Contains(t, strings.ToLower(err.Error()), "postgres query denied")
	requireUpstreamTableExists(t, upstreamAddr, "users")

	records := rec.records()
	require.Len(t, records, 1)
	require.Equal(t, "DROP", records[0].StatementClass)
	require.Equal(t, DecisionDeny, records[0].Decision)
}

func TestProxyNestedBlockCommentBypassExtendedDenied(t *testing.T) {
	upstreamAddr := startPasswordPostgres(t)
	execUpstream(t, upstreamAddr, "create table users (id int)")
	certs := newTestCerts(t)
	rec := &memoryRecorder{}
	policy := &fakePolicy{
		query: func(_ context.Context, req QueryRequest) (*Decision, error) {
			if req.StatementClass == "DROP" {
				return &Decision{Action: DecisionDeny, Reason: "DROP is not allowed"}, nil
			}
			return &Decision{Action: DecisionAllow}, nil
		},
	}
	proxyAddr, stop := startProxy(t, upstreamAddr, certs, policy, rec, nil)
	defer stop()

	conn := connectPGX(t, proxyAddr, certs, pgx.QueryExecModeCacheStatement)
	defer conn.Close(context.Background())

	_, err := conn.Exec(context.Background(), "/*/* */ SELECT */ DROP TABLE users")
	require.Error(t, err)
	require.Contains(t, strings.ToLower(err.Error()), "postgres query denied")
	requireUpstreamTableExists(t, upstreamAddr, "users")

	records := rec.records()
	require.Len(t, records, 1)
	require.Equal(t, "DROP", records[0].StatementClass)
	require.Equal(t, DecisionDeny, records[0].Decision)
}

func TestProxyRejectsMissingClientCertificate(t *testing.T) {
	upstreamAddr := startPasswordPostgres(t)
	certs := newTestCerts(t)
	proxyAddr, stop := startProxy(t, upstreamAddr, certs, &fakePolicy{}, &memoryRecorder{}, nil)
	defer stop()

	conn, err := connectPGXWithOptions(t, proxyAddr, certs, pgx.QueryExecModeSimpleProtocol, "alice", false)
	if conn != nil {
		defer conn.Close(context.Background())
	}
	require.Error(t, err)
}

func TestProxySessionPolicyDeniesDatabaseUser(t *testing.T) {
	upstreamAddr := startPasswordPostgres(t)
	certs := newTestCerts(t)
	policy := &fakePolicy{
		session: func(_ context.Context, session *Session) error {
			if session.DatabaseUser == "blocked" {
				return errors.New("database user is not allowed")
			}
			return nil
		},
	}
	proxyAddr, stop := startProxy(t, upstreamAddr, certs, policy, &memoryRecorder{}, nil)
	defer stop()

	conn, err := connectPGXWithOptions(t, proxyAddr, certs, pgx.QueryExecModeSimpleProtocol, "blocked", true)
	if conn != nil {
		defer conn.Close(context.Background())
	}
	require.Error(t, err)
	var pgErr *pgconn.PgError
	require.True(t, errors.As(err, &pgErr), "expected postgres error, got %T: %v", err, err)
	require.Equal(t, "42501", pgErr.Code)
}

func TestProxyStaticCredentialInjectionUsesUpstreamPassword(t *testing.T) {
	upstreamAddr := startPasswordPostgres(t)
	certs := newTestCerts(t)
	proxyAddr, stop := startProxy(t, upstreamAddr, certs, &fakePolicy{}, &memoryRecorder{}, nil)
	defer stop()

	conn := connectPGX(t, proxyAddr, certs, pgx.QueryExecModeSimpleProtocol)
	defer conn.Close(context.Background())

	var currentUser string
	require.NoError(t, conn.QueryRow(context.Background(), "select current_user").Scan(&currentUser))
	require.Equal(t, "pomeriumtest", currentUser)
}

func TestProxyStepUpFailsClosedAndRecords(t *testing.T) {
	upstreamAddr := startPasswordPostgres(t)
	certs := newTestCerts(t)
	rec := &memoryRecorder{}
	policy := &fakePolicy{
		query: func(_ context.Context, req QueryRequest) (*Decision, error) {
			if req.StatementClass == "SELECT" {
				return &Decision{Action: DecisionStepUp, Reason: "fresh approval required"}, nil
			}
			return &Decision{Action: DecisionAllow}, nil
		},
	}
	proxyAddr, stop := startProxy(t, upstreamAddr, certs, policy, rec, nil)
	defer stop()

	conn := connectPGX(t, proxyAddr, certs, pgx.QueryExecModeSimpleProtocol)
	defer conn.Close(context.Background())

	_, err := conn.Exec(context.Background(), "select 1")
	require.Error(t, err)
	require.Contains(t, strings.ToLower(err.Error()), "postgres query denied")

	records := rec.records()
	require.Len(t, records, 1)
	require.Equal(t, DecisionStepUp, records[0].Decision)
	require.Equal(t, "denied", records[0].Status)
	require.Equal(t, "fresh approval required", records[0].Reason)
}

func TestProxyUnknownPolicyDecisionFailsClosed(t *testing.T) {
	upstreamAddr := startPasswordPostgres(t)
	certs := newTestCerts(t)
	rec := &memoryRecorder{}
	policy := &fakePolicy{
		query: func(context.Context, QueryRequest) (*Decision, error) {
			return &Decision{Action: DecisionAction("typo")}, nil
		},
	}
	proxyAddr, stop := startProxy(t, upstreamAddr, certs, policy, rec, nil)
	defer stop()

	conn := connectPGX(t, proxyAddr, certs, pgx.QueryExecModeSimpleProtocol)
	defer conn.Close(context.Background())

	_, err := conn.Exec(context.Background(), "select 1")
	require.Error(t, err)

	records := rec.records()
	require.Len(t, records, 1)
	require.Equal(t, DecisionDeny, records[0].Decision)
	require.Contains(t, records[0].Reason, "unsupported postgres policy decision action")
}

func TestProxyQueryPolicyErrorFailsClosedBeforeUpstream(t *testing.T) {
	upstreamAddr := startPasswordPostgres(t)
	execUpstream(t, upstreamAddr, "create table policy_error_guard (id int)")
	certs := newTestCerts(t)
	rec := &memoryRecorder{}
	policy := &fakePolicy{
		query: func(context.Context, QueryRequest) (*Decision, error) {
			return nil, errors.New("policy backend unavailable")
		},
	}
	proxyAddr, stop := startProxy(t, upstreamAddr, certs, policy, rec, nil)
	defer stop()

	conn := connectPGX(t, proxyAddr, certs, pgx.QueryExecModeSimpleProtocol)
	defer conn.Close(context.Background())

	_, err := conn.Exec(context.Background(), "drop table policy_error_guard")
	require.Error(t, err)
	require.Contains(t, strings.ToLower(err.Error()), "postgres query denied")
	requireUpstreamTableExists(t, upstreamAddr, "policy_error_guard")

	records := rec.records()
	require.Len(t, records, 1)
	require.Equal(t, "DROP", records[0].StatementClass)
	require.Equal(t, DecisionDeny, records[0].Decision)
	require.Equal(t, "denied", records[0].Status)
	require.Contains(t, records[0].Reason, "policy backend unavailable")
}

func TestNormalizeDecisionDefaultsToDeny(t *testing.T) {
	got := normalizeDecision(nil, nil)
	require.Equal(t, DecisionDeny, got.Action)
	require.Contains(t, got.Reason, "empty postgres policy decision")
}

func TestAuthorizeQueryUsesAuthorizationTimeout(t *testing.T) {
	s := &Server{
		AuthorizationTimeout: 10 * time.Millisecond,
		Policy: &fakePolicy{
			query: func(ctx context.Context, _ QueryRequest) (*Decision, error) {
				<-ctx.Done()
				return nil, ctx.Err()
			},
		},
	}

	started := time.Now()
	decision := normalizeDecision(s.authorizeQuery(context.Background(), QueryRequest{}))
	require.Equal(t, DecisionDeny, decision.Action)
	require.Contains(t, decision.Reason, context.DeadlineExceeded.Error())
	require.Less(t, time.Since(started), time.Second)
}

func TestProxyQueryPolicyTimeoutFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name string
		mode pgx.QueryExecMode
	}{
		{name: "simple", mode: pgx.QueryExecModeSimpleProtocol},
		{name: "extended", mode: pgx.QueryExecModeCacheStatement},
	} {
		t.Run(tc.name, func(t *testing.T) {
			upstreamAddr := startPasswordPostgres(t)
			certs := newTestCerts(t)
			rec := &memoryRecorder{}
			policy := &fakePolicy{
				query: func(ctx context.Context, _ QueryRequest) (*Decision, error) {
					<-ctx.Done()
					return nil, ctx.Err()
				},
			}
			proxyAddr, stop := startProxyWithOptions(t, upstreamAddr, certs, policy, rec, nil, func(server *Server) {
				server.AuthorizationTimeout = 10 * time.Millisecond
			})
			defer stop()

			conn := connectPGX(t, proxyAddr, certs, tc.mode)
			defer conn.Close(context.Background())

			started := time.Now()
			_, err := conn.Exec(context.Background(), "select 1")
			require.Error(t, err)
			require.Less(t, time.Since(started), time.Second)
			require.Contains(t, strings.ToLower(err.Error()), "postgres query denied")

			records := rec.records()
			require.Len(t, records, 1)
			require.Equal(t, DecisionDeny, records[0].Decision)
			require.Equal(t, "denied", records[0].Status)
			require.Contains(t, records[0].Reason, context.DeadlineExceeded.Error())
		})
	}
}

func TestPeriodicReauthorizeRecoversAndClosesConnections(t *testing.T) {
	s := &Server{
		ReauthorizeInterval: 10 * time.Millisecond,
		Identity: &fakeIdentity{
			reauthorize: func(context.Context, *Session) error {
				panic("reauthorize panic")
			},
		},
	}
	clientRead, clientWrite := net.Pipe()
	upstreamRead, upstreamWrite := net.Pipe()
	defer clientRead.Close()
	defer upstreamRead.Close()
	require.NoError(t, clientRead.SetReadDeadline(time.Now().Add(time.Second)))
	require.NoError(t, upstreamRead.SetReadDeadline(time.Now().Add(time.Second)))

	stop := s.startPeriodicReauthorize(t.Context(), &Session{}, clientWrite, upstreamWrite)
	defer stop()

	buf := make([]byte, 1)
	_, err := clientRead.Read(buf)
	require.Error(t, err)
	_, err = upstreamRead.Read(buf)
	require.Error(t, err)
}

func TestProxyExtendedQueryRecordsRedactedParameters(t *testing.T) {
	upstreamAddr := startPasswordPostgres(t)
	certs := newTestCerts(t)
	rec := &memoryRecorder{}
	proxyAddr, stop := startProxy(t, upstreamAddr, certs, &fakePolicy{}, rec, nil)
	defer stop()

	conn := connectPGX(t, proxyAddr, certs, pgx.QueryExecModeCacheStatement)
	defer conn.Close(context.Background())

	var n int
	require.NoError(t, conn.QueryRow(context.Background(), "select $1::int + 1", 41).Scan(&n))
	require.Equal(t, 42, n)

	records := rec.records()
	require.Len(t, records, 1)
	require.Equal(t, QueryProtocolExtended, records[0].Protocol)
	require.Equal(t, "select $1::int + 1", records[0].SQL)
	require.Equal(t, 1, records[0].ParameterCount)
	require.True(t, records[0].ParametersRedacted)
	require.NotContains(t, records[0].SQL, "41")
	require.NotContains(t, records[0].Reason, "41")
	require.NotContains(t, records[0].ErrorMessage, "41")
}

func TestProxyFunctionCallFailsClosedAndRecords(t *testing.T) {
	upstreamAddr := startPasswordPostgres(t)
	certs := newTestCerts(t)
	rec := &memoryRecorder{}
	proxyAddr, stop := startProxy(t, upstreamAddr, certs, &fakePolicy{}, rec, nil)
	defer stop()

	frontend, conn, _ := connectDirectTLSFrontend(t, proxyAddr, certs)
	defer conn.Close()

	frontend.Send(&pgproto3.FunctionCall{Function: 1})
	require.NoError(t, frontend.Flush())
	errors, _ := readUntilReady(t, frontend)
	require.Len(t, errors, 1)
	require.Equal(t, "42501", errors[0].Code)

	records := rec.records()
	require.Len(t, records, 1)
	require.Equal(t, QueryProtocolFunctionCall, records[0].Protocol)
	require.Equal(t, "FUNCTION_CALL", records[0].StatementClass)
	require.Equal(t, DecisionDeny, records[0].Decision)
}

func TestProxyUnsupportedFrontendMessageFailsVisible(t *testing.T) {
	upstreamAddr := startPasswordPostgres(t)
	certs := newTestCerts(t)
	proxyAddr, stop := startProxy(t, upstreamAddr, certs, &fakePolicy{}, &memoryRecorder{}, nil)
	defer stop()

	frontend, conn, _ := connectDirectTLSFrontend(t, proxyAddr, certs)
	defer conn.Close()

	frontend.Send(&pgproto3.CopyData{Data: []byte("orphan copy data")})
	require.NoError(t, frontend.Flush())

	errors, _ := readUntilReady(t, frontend)
	require.Len(t, errors, 1)
	require.Equal(t, "0A000", errors[0].Code)
	require.Contains(t, errors[0].Detail, "CopyData")
	requireFrontendSimpleQuery(t, frontend, "select 1", "1")
}

func TestProxyExtendedUnsupportedMessageBeforeSyncFailsVisible(t *testing.T) {
	upstreamAddr := startPasswordPostgres(t)
	certs := newTestCerts(t)
	proxyAddr, stop := startProxy(t, upstreamAddr, certs, &fakePolicy{}, &memoryRecorder{}, nil)
	defer stop()

	frontend, conn, _ := connectDirectTLSFrontend(t, proxyAddr, certs)
	defer conn.Close()

	frontend.Send(&pgproto3.Parse{Name: "stmt1", Query: "select 1"})
	frontend.Send(&pgproto3.CopyData{Data: []byte("orphan copy data")})
	frontend.Send(&pgproto3.Sync{})
	require.NoError(t, frontend.Flush())

	errors, _ := readUntilReady(t, frontend)
	require.Len(t, errors, 1)
	require.Equal(t, "0A000", errors[0].Code)
	require.Contains(t, errors[0].Detail, "CopyData")
	requireFrontendSimpleQuery(t, frontend, "select 1", "1")
}

func TestProxyExtendedDenyDoesNotDesyncConnection(t *testing.T) {
	upstreamAddr := startPasswordPostgres(t)
	certs := newTestCerts(t)
	rec := &memoryRecorder{}
	policy := &fakePolicy{
		query: func(_ context.Context, req QueryRequest) (*Decision, error) {
			if req.StatementClass == "DROP" {
				return &Decision{Action: DecisionDeny, Reason: "DROP is not allowed"}, nil
			}
			return &Decision{Action: DecisionAllow}, nil
		},
	}
	proxyAddr, stop := startProxy(t, upstreamAddr, certs, policy, rec, nil)
	defer stop()

	conn := connectPGX(t, proxyAddr, certs, pgx.QueryExecModeCacheStatement)
	defer conn.Close(context.Background())

	_, err := conn.Exec(context.Background(), "drop table if exists blocked_target")
	require.Error(t, err)

	var n int
	require.NoError(t, conn.QueryRow(context.Background(), "select $1::int", 7).Scan(&n))
	require.Equal(t, 7, n)

	records := rec.records()
	require.Len(t, records, 2)
	require.Equal(t, DecisionDeny, records[0].Decision)
	require.Equal(t, "DROP", records[0].StatementClass)
	require.Equal(t, DecisionAllow, records[1].Decision)
	require.Equal(t, "SELECT", records[1].StatementClass)
}

func TestProxyExtendedBackendErrorDoesNotCommitPendingState(t *testing.T) {
	upstreamAddr := startPasswordPostgres(t)
	certs := newTestCerts(t)
	proxyAddr, stop := startProxy(t, upstreamAddr, certs, &fakePolicy{}, &memoryRecorder{}, nil)
	defer stop()

	frontend, conn, _ := connectDirectTLSFrontend(t, proxyAddr, certs)
	defer conn.Close()

	frontend.Send(&pgproto3.Parse{Name: "stmt", Query: "select 1"})
	frontend.Send(&pgproto3.Sync{})
	require.NoError(t, frontend.Flush())
	errors, _ := readUntilReady(t, frontend)
	require.Empty(t, errors)

	frontend.Send(&pgproto3.Parse{Name: "stmt", Query: "select 2"})
	frontend.Send(&pgproto3.Sync{})
	require.NoError(t, frontend.Flush())
	errors, _ = readUntilReady(t, frontend)
	require.Len(t, errors, 1)

	frontend.Send(&pgproto3.Bind{DestinationPortal: "portal", PreparedStatement: "stmt"})
	frontend.Send(&pgproto3.Execute{Portal: "portal", MaxRows: 1})
	frontend.Send(&pgproto3.Sync{})
	require.NoError(t, frontend.Flush())
	require.Equal(t, []string{"1"}, readRowsUntilReady(t, frontend))
}

func TestProxyExtendedPartialBatchParseErrorCommitsOnlyConfirmedStatementsForAudit(t *testing.T) {
	upstreamAddr := startPasswordPostgres(t)
	certs := newTestCerts(t)
	rec := &memoryRecorder{}
	proxyAddr, stop := startProxy(t, upstreamAddr, certs, &fakePolicy{}, rec, nil)
	defer stop()

	frontend, conn, _ := connectDirectTLSFrontend(t, proxyAddr, certs)
	defer conn.Close()

	frontend.Send(&pgproto3.Parse{Name: "a", Query: "select 1"})
	frontend.Send(&pgproto3.Parse{Name: "b", Query: "select from"})
	frontend.Send(&pgproto3.Sync{})
	require.NoError(t, frontend.Flush())
	errors, _ := readUntilReady(t, frontend)
	require.Len(t, errors, 1)
	require.Equal(t, "42601", errors[0].Code)

	frontend.Send(&pgproto3.Bind{DestinationPortal: "portal-a", PreparedStatement: "a"})
	frontend.Send(&pgproto3.Execute{Portal: "portal-a"})
	frontend.Send(&pgproto3.Sync{})
	require.NoError(t, frontend.Flush())
	require.Equal(t, []string{"1"}, readRowsUntilReady(t, frontend))

	frontend.Send(&pgproto3.Bind{DestinationPortal: "portal-b", PreparedStatement: "b"})
	frontend.Send(&pgproto3.Execute{Portal: "portal-b"})
	frontend.Send(&pgproto3.Sync{})
	require.NoError(t, frontend.Flush())
	errors, _ = readUntilReady(t, frontend)
	require.Len(t, errors, 1)
	require.Equal(t, "26000", errors[0].Code)

	records := rec.records()
	require.Len(t, records, 2)
	require.Equal(t, "select 1", records[0].SQL)
	require.Equal(t, "SELECT", records[0].StatementClass)
	require.Equal(t, "ok", records[0].Status)
	require.Empty(t, records[1].SQL)
	require.Equal(t, "EMPTY", records[1].StatementClass)
	require.Equal(t, "error", records[1].Status)
	require.Equal(t, "26000", records[1].ErrorCode)
}

func TestProxyExtendedPartialBatchErrorDoesNotRecordSkippedExecute(t *testing.T) {
	upstreamAddr := startPasswordPostgres(t)
	certs := newTestCerts(t)
	rec := &memoryRecorder{}
	proxyAddr, stop := startProxy(t, upstreamAddr, certs, &fakePolicy{}, rec, nil)
	defer stop()

	frontend, conn, _ := connectDirectTLSFrontend(t, proxyAddr, certs)
	defer conn.Close()

	frontend.Send(&pgproto3.Parse{Name: "a", Query: "select 1"})
	frontend.Send(&pgproto3.Bind{DestinationPortal: "portal-a", PreparedStatement: "a"})
	frontend.Send(&pgproto3.Parse{Name: "bad", Query: "select from"})
	frontend.Send(&pgproto3.Execute{Portal: "portal-a"})
	frontend.Send(&pgproto3.Sync{})
	require.NoError(t, frontend.Flush())
	errors, _ := readUntilReady(t, frontend)
	require.Len(t, errors, 1)
	require.Equal(t, "42601", errors[0].Code)
	require.Empty(t, rec.records())

	frontend.Send(&pgproto3.Bind{DestinationPortal: "portal-a2", PreparedStatement: "a"})
	frontend.Send(&pgproto3.Execute{Portal: "portal-a2"})
	frontend.Send(&pgproto3.Sync{})
	require.NoError(t, frontend.Flush())

	require.Equal(t, []string{"1"}, readRowsUntilReady(t, frontend))
	records := rec.records()
	require.Len(t, records, 1)
	require.Equal(t, "select 1", records[0].SQL)
	require.Equal(t, "SELECT", records[0].StatementClass)
	require.Equal(t, "ok", records[0].Status)
}

func TestProxyExtendedExecuteErrorPreservesPreparedStatementForAudit(t *testing.T) {
	upstreamAddr := startPasswordPostgres(t)
	certs := newTestCerts(t)
	rec := &memoryRecorder{}
	proxyAddr, stop := startProxy(t, upstreamAddr, certs, &fakePolicy{}, rec, nil)
	defer stop()

	frontend, conn, _ := connectDirectTLSFrontend(t, proxyAddr, certs)
	defer conn.Close()

	frontend.Send(&pgproto3.Parse{Name: "divide", Query: "select 10 / $1::int", ParameterOIDs: []uint32{23}})
	frontend.Send(&pgproto3.Bind{DestinationPortal: "bad", PreparedStatement: "divide", Parameters: [][]byte{[]byte("0")}})
	frontend.Send(&pgproto3.Execute{Portal: "bad"})
	frontend.Send(&pgproto3.Sync{})
	require.NoError(t, frontend.Flush())

	errors, _ := readUntilReady(t, frontend)
	require.Len(t, errors, 1)
	require.Equal(t, "22012", errors[0].Code)

	frontend.Send(&pgproto3.Execute{Portal: "bad"})
	frontend.Send(&pgproto3.Sync{})
	require.NoError(t, frontend.Flush())

	errors, _ = readUntilReady(t, frontend)
	require.Len(t, errors, 1)
	require.Equal(t, "34000", errors[0].Code)

	frontend.Send(&pgproto3.Bind{DestinationPortal: "good", PreparedStatement: "divide", Parameters: [][]byte{[]byte("2")}})
	frontend.Send(&pgproto3.Execute{Portal: "good"})
	frontend.Send(&pgproto3.Sync{})
	require.NoError(t, frontend.Flush())

	require.Equal(t, []string{"5"}, readRowsUntilReady(t, frontend))
	records := rec.records()
	require.Len(t, records, 3)
	require.Equal(t, "select 10 / $1::int", records[0].SQL)
	require.Equal(t, "SELECT", records[0].StatementClass)
	require.Equal(t, "error", records[0].Status)
	require.Equal(t, "22012", records[0].ErrorCode)
	require.Empty(t, records[1].SQL)
	require.Equal(t, "EMPTY", records[1].StatementClass)
	require.Equal(t, "error", records[1].Status)
	require.Equal(t, "34000", records[1].ErrorCode)
	require.Equal(t, "select 10 / $1::int", records[2].SQL)
	require.Equal(t, "SELECT", records[2].StatementClass)
	require.Equal(t, "ok", records[2].Status)
	require.Equal(t, 1, records[2].ParameterCount)
	require.True(t, records[2].ParametersRedacted)
}

func TestProxyExtendedCloseStatementKeepsBoundPortalForAudit(t *testing.T) {
	upstreamAddr := startPasswordPostgres(t)
	certs := newTestCerts(t)
	rec := &memoryRecorder{}
	proxyAddr, stop := startProxy(t, upstreamAddr, certs, &fakePolicy{}, rec, nil)
	defer stop()

	frontend, conn, _ := connectDirectTLSFrontend(t, proxyAddr, certs)
	defer conn.Close()

	frontend.Send(&pgproto3.Query{String: "begin"})
	require.NoError(t, frontend.Flush())
	errors, txStatus := readUntilReady(t, frontend)
	require.Empty(t, errors)
	require.Equal(t, byte('T'), txStatus)

	frontend.Send(&pgproto3.Parse{Name: "stmt", Query: "select 1"})
	frontend.Send(&pgproto3.Bind{DestinationPortal: "portal", PreparedStatement: "stmt"})
	frontend.Send(&pgproto3.Sync{})
	require.NoError(t, frontend.Flush())
	errors, txStatus = readUntilReady(t, frontend)
	require.Empty(t, errors)
	require.Equal(t, byte('T'), txStatus)

	frontend.Send(&pgproto3.Close{ObjectType: 'S', Name: "stmt"})
	frontend.Send(&pgproto3.Sync{})
	require.NoError(t, frontend.Flush())
	errors, txStatus = readUntilReady(t, frontend)
	require.Empty(t, errors)
	require.Equal(t, byte('T'), txStatus)

	frontend.Send(&pgproto3.Execute{Portal: "portal"})
	frontend.Send(&pgproto3.Sync{})
	require.NoError(t, frontend.Flush())
	require.Equal(t, []string{"1"}, readRowsUntilReady(t, frontend))
	records := rec.records()
	require.Len(t, records, 2)
	require.Equal(t, QueryProtocolSimple, records[0].Protocol)
	require.Equal(t, QueryProtocolExtended, records[1].Protocol)
	require.Equal(t, "select 1", records[1].SQL)
	require.Equal(t, "SELECT", records[1].StatementClass)
	require.Equal(t, "ok", records[1].Status)
	require.Equal(t, 1, records[1].Rows)
}

func TestProxyUnnamedParseErrorClearsPreviousUnnamedStatementForAudit(t *testing.T) {
	upstreamAddr := startPasswordPostgres(t)
	certs := newTestCerts(t)
	rec := &memoryRecorder{}
	proxyAddr, stop := startProxy(t, upstreamAddr, certs, &fakePolicy{}, rec, nil)
	defer stop()

	frontend, conn, _ := connectDirectTLSFrontend(t, proxyAddr, certs)
	defer conn.Close()

	frontend.Send(&pgproto3.Parse{Query: "select 1"})
	frontend.Send(&pgproto3.Sync{})
	require.NoError(t, frontend.Flush())
	errors, _ := readUntilReady(t, frontend)
	require.Empty(t, errors)

	frontend.Send(&pgproto3.Parse{Query: "select from"})
	frontend.Send(&pgproto3.Sync{})
	require.NoError(t, frontend.Flush())
	errors, _ = readUntilReady(t, frontend)
	require.Len(t, errors, 1)
	require.Equal(t, "42601", errors[0].Code)

	frontend.Send(&pgproto3.Bind{})
	frontend.Send(&pgproto3.Execute{})
	frontend.Send(&pgproto3.Sync{})
	require.NoError(t, frontend.Flush())
	errors, _ = readUntilReady(t, frontend)
	require.Len(t, errors, 1)
	require.Equal(t, "26000", errors[0].Code)

	records := rec.records()
	require.Len(t, records, 1)
	require.Empty(t, records[0].SQL)
	require.Equal(t, "EMPTY", records[0].StatementClass)
	require.Equal(t, "error", records[0].Status)
	require.Equal(t, "26000", records[0].ErrorCode)
}

func TestProxySimpleQueryClearsUnnamedExtendedStateForAudit(t *testing.T) {
	upstreamAddr := startPasswordPostgres(t)
	certs := newTestCerts(t)
	rec := &memoryRecorder{}
	proxyAddr, stop := startProxy(t, upstreamAddr, certs, &fakePolicy{}, rec, nil)
	defer stop()

	frontend, conn, _ := connectDirectTLSFrontend(t, proxyAddr, certs)
	defer conn.Close()

	frontend.Send(&pgproto3.Query{String: "begin"})
	require.NoError(t, frontend.Flush())
	errors, txStatus := readUntilReady(t, frontend)
	require.Empty(t, errors)
	require.Equal(t, byte('T'), txStatus)

	frontend.Send(&pgproto3.Parse{Query: "select 1"})
	frontend.Send(&pgproto3.Bind{})
	frontend.Send(&pgproto3.Sync{})
	require.NoError(t, frontend.Flush())
	errors, txStatus = readUntilReady(t, frontend)
	require.Empty(t, errors)
	require.Equal(t, byte('T'), txStatus)

	frontend.Send(&pgproto3.Query{String: "select 2"})
	require.NoError(t, frontend.Flush())
	errors, txStatus = readUntilReady(t, frontend)
	require.Empty(t, errors)
	require.Equal(t, byte('T'), txStatus)

	frontend.Send(&pgproto3.Bind{})
	frontend.Send(&pgproto3.Execute{})
	frontend.Send(&pgproto3.Sync{})
	require.NoError(t, frontend.Flush())
	errors, _ = readUntilReady(t, frontend)
	require.Len(t, errors, 1)
	require.Equal(t, "26000", errors[0].Code)

	records := rec.records()
	require.Len(t, records, 3)
	require.Equal(t, QueryProtocolSimple, records[0].Protocol)
	require.Equal(t, QueryProtocolSimple, records[1].Protocol)
	require.Equal(t, QueryProtocolExtended, records[2].Protocol)
	require.Empty(t, records[2].SQL)
	require.Equal(t, "EMPTY", records[2].StatementClass)
	require.Equal(t, "error", records[2].Status)
	require.Equal(t, "26000", records[2].ErrorCode)
}

func TestProxyDescribeErrorBeforeUnnamedParseKeepsPreviousUnnamedStatementForAudit(t *testing.T) {
	upstreamAddr := startPasswordPostgres(t)
	certs := newTestCerts(t)
	rec := &memoryRecorder{}
	proxyAddr, stop := startProxy(t, upstreamAddr, certs, &fakePolicy{}, rec, nil)
	defer stop()

	frontend, conn, _ := connectDirectTLSFrontend(t, proxyAddr, certs)
	defer conn.Close()

	frontend.Send(&pgproto3.Parse{Query: "select 1"})
	frontend.Send(&pgproto3.Sync{})
	require.NoError(t, frontend.Flush())
	errors, _ := readUntilReady(t, frontend)
	require.Empty(t, errors)

	frontend.Send(&pgproto3.Describe{ObjectType: 'S', Name: "missing"})
	frontend.Send(&pgproto3.Parse{Query: "select 2"})
	frontend.Send(&pgproto3.Sync{})
	require.NoError(t, frontend.Flush())
	errors, _ = readUntilReady(t, frontend)
	require.Len(t, errors, 1)
	require.Equal(t, "26000", errors[0].Code)

	frontend.Send(&pgproto3.Bind{})
	frontend.Send(&pgproto3.Execute{})
	frontend.Send(&pgproto3.Sync{})
	require.NoError(t, frontend.Flush())

	require.Equal(t, []string{"1"}, readRowsUntilReady(t, frontend))
	records := rec.records()
	require.Len(t, records, 1)
	require.Equal(t, "select 1", records[0].SQL)
	require.Equal(t, "SELECT", records[0].StatementClass)
	require.Equal(t, "ok", records[0].Status)
	require.Equal(t, 1, records[0].Rows)
}

func TestProxyInvalidCloseBeforeUnnamedParseKeepsPreviousUnnamedStatementForAudit(t *testing.T) {
	upstreamAddr := startPasswordPostgres(t)
	certs := newTestCerts(t)
	rec := &memoryRecorder{}
	proxyAddr, stop := startProxy(t, upstreamAddr, certs, &fakePolicy{}, rec, nil)
	defer stop()

	frontend, conn, _ := connectDirectTLSFrontend(t, proxyAddr, certs)
	defer conn.Close()

	frontend.Send(&pgproto3.Parse{Query: "select 1"})
	frontend.Send(&pgproto3.Sync{})
	require.NoError(t, frontend.Flush())
	errors, _ := readUntilReady(t, frontend)
	require.Empty(t, errors)

	frontend.Send(&pgproto3.Close{ObjectType: 'X', Name: "bad-close-type"})
	frontend.Send(&pgproto3.Parse{Query: "select 2"})
	frontend.Send(&pgproto3.Sync{})
	require.NoError(t, frontend.Flush())
	errors, _ = readUntilReady(t, frontend)
	require.Len(t, errors, 1)
	require.Equal(t, "08P01", errors[0].Code)

	frontend.Send(&pgproto3.Bind{})
	frontend.Send(&pgproto3.Execute{})
	frontend.Send(&pgproto3.Sync{})
	require.NoError(t, frontend.Flush())

	require.Equal(t, []string{"1"}, readRowsUntilReady(t, frontend))
	records := rec.records()
	require.Len(t, records, 1)
	require.Equal(t, "select 1", records[0].SQL)
	require.Equal(t, "SELECT", records[0].StatementClass)
	require.Equal(t, "ok", records[0].Status)
	require.Equal(t, 1, records[0].Rows)
}

func TestProxyExtendedDescribeWithoutExecuteAuthorizesBeforeMetadata(t *testing.T) {
	upstreamAddr := startPasswordPostgres(t)
	certs := newTestCerts(t)
	rec := &memoryRecorder{}
	var policyCalls atomic.Int32
	policy := &fakePolicy{
		query: func(context.Context, QueryRequest) (*Decision, error) {
			policyCalls.Add(1)
			return &Decision{Action: DecisionDeny, Reason: "metadata denied"}, nil
		},
	}
	proxyAddr, stop := startProxy(t, upstreamAddr, certs, policy, rec, nil)
	defer stop()

	frontend, conn, _ := connectDirectTLSFrontend(t, proxyAddr, certs)
	defer conn.Close()

	frontend.Send(&pgproto3.Parse{Name: "typed", Query: "select $1::int + 1", ParameterOIDs: []uint32{23}})
	frontend.Send(&pgproto3.Describe{ObjectType: 'S', Name: "typed"})
	frontend.Send(&pgproto3.Sync{})
	require.NoError(t, frontend.Flush())
	result := readMessagesUntilReady(t, frontend)
	require.Len(t, result.errors, 1)
	require.Equal(t, "42501", result.errors[0].Code)
	require.Contains(t, result.errors[0].Detail, "metadata denied")
	require.Equal(t, []string{
		"ErrorResponse",
		"ReadyForQuery",
	}, result.types)
	require.Equal(t, int32(2), policyCalls.Load())

	records := rec.records()
	require.Len(t, records, 1)
	require.Equal(t, "select $1::int + 1", records[0].SQL)
	require.Equal(t, "SELECT", records[0].StatementClass)
	require.Equal(t, DecisionDeny, records[0].Decision)
	require.Equal(t, "metadata denied", records[0].Reason)
	require.Equal(t, "denied", records[0].Status)
}

func TestProxyExtendedMixedBatchDescribeAuthorizesForbiddenStatementBeforeMetadata(t *testing.T) {
	upstreamAddr := startPasswordPostgres(t)
	execUpstream(t, upstreamAddr, "create table secret_table (id int, ssn text)")
	certs := newTestCerts(t)
	rec := &memoryRecorder{}
	var allowedCalls atomic.Int32
	var forbiddenCalls atomic.Int32
	policy := &fakePolicy{
		query: func(_ context.Context, req QueryRequest) (*Decision, error) {
			if strings.Contains(req.SQL, "secret_table") {
				forbiddenCalls.Add(1)
				return &Decision{Action: DecisionDeny, Reason: "secret table denied"}, nil
			}
			allowedCalls.Add(1)
			return &Decision{Action: DecisionAllow}, nil
		},
	}
	proxyAddr, stop := startProxy(t, upstreamAddr, certs, policy, rec, nil)
	defer stop()

	frontend, conn, _ := connectDirectTLSFrontend(t, proxyAddr, certs)
	defer conn.Close()

	frontend.Send(&pgproto3.Parse{Name: "A", Query: "select 1"})
	frontend.Send(&pgproto3.Parse{Name: "B", Query: "select id, ssn from secret_table"})
	frontend.Send(&pgproto3.Bind{DestinationPortal: "portalA", PreparedStatement: "A"})
	frontend.Send(&pgproto3.Describe{ObjectType: 'S', Name: "B"})
	frontend.Send(&pgproto3.Execute{Portal: "portalA"})
	frontend.Send(&pgproto3.Sync{})
	require.NoError(t, frontend.Flush())

	result := readMessagesUntilReady(t, frontend)
	require.Equal(t, []string{
		"ErrorResponse",
		"ReadyForQuery",
	}, result.types)
	require.Len(t, result.errors, 1)
	require.Equal(t, "42501", result.errors[0].Code)
	require.Contains(t, result.errors[0].Detail, "secret table denied")
	require.GreaterOrEqual(t, allowedCalls.Load(), int32(1))
	require.Equal(t, int32(2), forbiddenCalls.Load())

	records := rec.records()
	require.Len(t, records, 1)
	require.Equal(t, "select id, ssn from secret_table", records[0].SQL)
	require.Equal(t, "SELECT", records[0].StatementClass)
	require.Equal(t, DecisionDeny, records[0].Decision)
	require.Equal(t, "secret table denied", records[0].Reason)
	require.Equal(t, "denied", records[0].Status)
}

func TestProxyExtendedParseWithoutExecuteAuthorizesBeforeUpstream(t *testing.T) {
	upstreamAddr := startPasswordPostgres(t)
	certs := newTestCerts(t)
	rec := &memoryRecorder{}
	var policyCalls atomic.Int32
	policy := &fakePolicy{
		query: func(context.Context, QueryRequest) (*Decision, error) {
			policyCalls.Add(1)
			return &Decision{Action: DecisionDeny, Reason: "parse denied"}, nil
		},
	}
	proxyAddr, stop := startProxy(t, upstreamAddr, certs, policy, rec, nil)
	defer stop()

	frontend, conn, _ := connectDirectTLSFrontend(t, proxyAddr, certs)
	defer conn.Close()

	frontend.Send(&pgproto3.Parse{Name: "drop_stmt", Query: "drop table"})
	frontend.Send(&pgproto3.Sync{})
	require.NoError(t, frontend.Flush())
	result := readMessagesUntilReady(t, frontend)
	require.Equal(t, []string{
		"ErrorResponse",
		"ReadyForQuery",
	}, result.types)
	require.Len(t, result.errors, 1)
	require.Equal(t, "42501", result.errors[0].Code)
	require.Contains(t, result.errors[0].Detail, "parse denied")
	require.Equal(t, int32(1), policyCalls.Load())

	records := rec.records()
	require.Len(t, records, 1)
	require.Equal(t, "drop table", records[0].SQL)
	require.Equal(t, "DROP", records[0].StatementClass)
	require.Equal(t, DecisionDeny, records[0].Decision)
	require.Equal(t, "parse denied", records[0].Reason)
	require.Equal(t, "denied", records[0].Status)
}

func TestProxyExtendedPortalSuspendedRecordsExecute(t *testing.T) {
	upstreamAddr := startPasswordPostgres(t)
	certs := newTestCerts(t)
	rec := &memoryRecorder{}
	proxyAddr, stop := startProxy(t, upstreamAddr, certs, &fakePolicy{}, rec, nil)
	defer stop()

	frontend, conn, _ := connectDirectTLSFrontend(t, proxyAddr, certs)
	defer conn.Close()

	frontend.Send(&pgproto3.Query{String: "begin"})
	require.NoError(t, frontend.Flush())
	errors, txStatus := readUntilReady(t, frontend)
	require.Empty(t, errors)
	require.Equal(t, byte('T'), txStatus)

	frontend.Send(&pgproto3.Parse{Name: "series", Query: "select generate_series(1, 3)"})
	frontend.Send(&pgproto3.Bind{DestinationPortal: "portal", PreparedStatement: "series"})
	frontend.Send(&pgproto3.Execute{Portal: "portal", MaxRows: 1})
	frontend.Send(&pgproto3.Sync{})
	require.NoError(t, frontend.Flush())

	result := readMessagesUntilReady(t, frontend)
	require.Empty(t, result.errors)
	require.Equal(t, []string{"1"}, result.values)
	require.Equal(t, []string{"ParseComplete", "BindComplete", "DataRow", "PortalSuspended", "ReadyForQuery"}, result.types)
	require.Equal(t, byte('T'), result.txStatus)

	frontend.Send(&pgproto3.Execute{Portal: "portal", MaxRows: 1})
	frontend.Send(&pgproto3.Sync{})
	require.NoError(t, frontend.Flush())

	result = readMessagesUntilReady(t, frontend)
	require.Empty(t, result.errors)
	require.Equal(t, []string{"2"}, result.values)
	require.Equal(t, []string{"DataRow", "PortalSuspended", "ReadyForQuery"}, result.types)
	require.Equal(t, byte('T'), result.txStatus)

	frontend.Send(&pgproto3.Execute{Portal: "portal"})
	frontend.Send(&pgproto3.Sync{})
	require.NoError(t, frontend.Flush())

	result = readMessagesUntilReady(t, frontend)
	require.Empty(t, result.errors)
	require.Equal(t, []string{"3"}, result.values)
	require.Equal(t, []string{"DataRow", "CommandComplete", "ReadyForQuery"}, result.types)
	require.Equal(t, byte('T'), result.txStatus)

	records := rec.records()
	require.Len(t, records, 4)
	require.Equal(t, QueryProtocolSimple, records[0].Protocol)
	require.Equal(t, QueryProtocolExtended, records[1].Protocol)
	require.Equal(t, "select generate_series(1, 3)", records[1].SQL)
	require.Equal(t, "SELECT", records[1].StatementClass)
	require.Equal(t, "ok", records[1].Status)
	require.Equal(t, 1, records[1].Rows)
	require.Empty(t, records[1].CommandTag)
	require.Equal(t, QueryProtocolExtended, records[2].Protocol)
	require.Equal(t, "select generate_series(1, 3)", records[2].SQL)
	require.Equal(t, "SELECT", records[2].StatementClass)
	require.Equal(t, "ok", records[2].Status)
	require.Equal(t, 1, records[2].Rows)
	require.Empty(t, records[2].CommandTag)
	require.Equal(t, QueryProtocolExtended, records[3].Protocol)
	require.Equal(t, "select generate_series(1, 3)", records[3].SQL)
	require.Equal(t, "SELECT", records[3].StatementClass)
	require.Equal(t, "ok", records[3].Status)
	require.Equal(t, 1, records[3].Rows)
	require.Equal(t, "SELECT 1", records[3].CommandTag)
}

func TestProxyDenyInsideTransactionAbortsClientTransaction(t *testing.T) {
	upstreamAddr := startPasswordPostgres(t)
	execUpstream(t, upstreamAddr, "create table tx_guard (id int)")
	certs := newTestCerts(t)
	rec := &memoryRecorder{}
	policy := &fakePolicy{
		query: func(_ context.Context, req QueryRequest) (*Decision, error) {
			if req.StatementClass == "DROP" {
				return &Decision{Action: DecisionDeny, Reason: "DROP is not allowed"}, nil
			}
			return &Decision{Action: DecisionAllow}, nil
		},
	}
	proxyAddr, stop := startProxy(t, upstreamAddr, certs, policy, rec, nil)
	defer stop()

	frontend, conn, _ := connectDirectTLSFrontend(t, proxyAddr, certs)
	defer conn.Close()

	frontend.Send(&pgproto3.Query{String: "begin"})
	require.NoError(t, frontend.Flush())
	_, txStatus := readUntilReady(t, frontend)
	require.Equal(t, byte('T'), txStatus)

	frontend.Send(&pgproto3.Query{String: "insert into tx_guard values (1)"})
	require.NoError(t, frontend.Flush())
	errors, txStatus := readUntilReady(t, frontend)
	require.Empty(t, errors)
	require.Equal(t, byte('T'), txStatus)

	frontend.Send(&pgproto3.Query{String: "drop table if exists blocked_target"})
	require.NoError(t, frontend.Flush())
	errors, txStatus = readUntilReady(t, frontend)
	require.Len(t, errors, 1)
	require.Equal(t, "42501", errors[0].Code)
	require.Equal(t, byte('E'), txStatus)

	frontend.Send(&pgproto3.Query{String: "insert into tx_guard values (2)"})
	require.NoError(t, frontend.Flush())
	errors, txStatus = readUntilReady(t, frontend)
	require.Len(t, errors, 1)
	require.Equal(t, "25P02", errors[0].Code)
	require.Equal(t, byte('E'), txStatus)

	frontend.Send(&pgproto3.Query{String: "commit"})
	require.NoError(t, frontend.Flush())
	errors, txStatus = readUntilReady(t, frontend)
	require.Len(t, errors, 1)
	require.Equal(t, "25P02", errors[0].Code)
	require.Equal(t, byte('E'), txStatus)

	frontend.Send(&pgproto3.Query{String: "rollback"})
	require.NoError(t, frontend.Flush())
	errors, txStatus = readUntilReady(t, frontend)
	require.Empty(t, errors)
	require.Equal(t, byte('I'), txStatus)

	requireUpstreamTableCount(t, upstreamAddr, "tx_guard", 0)

	records := rec.records()
	require.Len(t, records, 6)
	require.Equal(t, "DROP", records[2].StatementClass)
	require.Equal(t, "42501", records[2].ErrorCode)
	require.Equal(t, "INSERT", records[3].StatementClass)
	require.Equal(t, "25P02", records[3].ErrorCode)
	require.Equal(t, "COMMIT", records[4].StatementClass)
	require.Equal(t, "25P02", records[4].ErrorCode)
	require.Equal(t, "ROLLBACK", records[5].StatementClass)
	require.Equal(t, "ok", records[5].Status)
}

func TestProxyExtendedDenyInsideTransactionAbortsClientTransaction(t *testing.T) {
	upstreamAddr := startPasswordPostgres(t)
	execUpstream(t, upstreamAddr, "create table tx_guard (id int)")
	certs := newTestCerts(t)
	rec := &memoryRecorder{}
	policy := &fakePolicy{
		query: func(_ context.Context, req QueryRequest) (*Decision, error) {
			if req.StatementClass == "DROP" {
				return &Decision{Action: DecisionDeny, Reason: "DROP is not allowed"}, nil
			}
			return &Decision{Action: DecisionAllow}, nil
		},
	}
	proxyAddr, stop := startProxy(t, upstreamAddr, certs, policy, rec, nil)
	defer stop()

	frontend, conn, _ := connectDirectTLSFrontend(t, proxyAddr, certs)
	defer conn.Close()

	frontend.Send(&pgproto3.Query{String: "begin"})
	require.NoError(t, frontend.Flush())
	_, txStatus := readUntilReady(t, frontend)
	require.Equal(t, byte('T'), txStatus)

	frontend.Send(&pgproto3.Query{String: "insert into tx_guard values (1)"})
	require.NoError(t, frontend.Flush())
	errors, txStatus := readUntilReady(t, frontend)
	require.Empty(t, errors)
	require.Equal(t, byte('T'), txStatus)

	frontend.Send(&pgproto3.Parse{Name: "drop_stmt", Query: "drop table if exists blocked_target"})
	frontend.Send(&pgproto3.Bind{DestinationPortal: "drop_portal", PreparedStatement: "drop_stmt"})
	frontend.Send(&pgproto3.Execute{Portal: "drop_portal"})
	frontend.Send(&pgproto3.Sync{})
	require.NoError(t, frontend.Flush())
	errors, txStatus = readUntilReady(t, frontend)
	require.Len(t, errors, 1)
	require.Equal(t, "42501", errors[0].Code)
	require.Equal(t, byte('E'), txStatus)

	frontend.Send(&pgproto3.Parse{Name: "insert_stmt", Query: "insert into tx_guard values (2)"})
	frontend.Send(&pgproto3.Bind{DestinationPortal: "insert_portal", PreparedStatement: "insert_stmt"})
	frontend.Send(&pgproto3.Execute{Portal: "insert_portal"})
	frontend.Send(&pgproto3.Sync{})
	require.NoError(t, frontend.Flush())
	errors, txStatus = readUntilReady(t, frontend)
	require.Len(t, errors, 1)
	require.Equal(t, "25P02", errors[0].Code)
	require.Equal(t, byte('E'), txStatus)

	frontend.Send(&pgproto3.Query{String: "rollback"})
	require.NoError(t, frontend.Flush())
	errors, txStatus = readUntilReady(t, frontend)
	require.Empty(t, errors)
	require.Equal(t, byte('I'), txStatus)

	requireUpstreamTableCount(t, upstreamAddr, "tx_guard", 0)

	records := rec.records()
	require.Len(t, records, 5)
	require.Equal(t, QueryProtocolExtended, records[2].Protocol)
	require.Equal(t, "DROP", records[2].StatementClass)
	require.Equal(t, "42501", records[2].ErrorCode)
	require.Equal(t, QueryProtocolExtended, records[3].Protocol)
	require.Equal(t, "INSERT", records[3].StatementClass)
	require.Equal(t, "25P02", records[3].ErrorCode)
	require.Equal(t, "ROLLBACK", records[4].StatementClass)
	require.Equal(t, "ok", records[4].Status)
}

func TestProxyDirectTLSStartup(t *testing.T) {
	upstreamAddr := startPasswordPostgres(t)
	certs := newTestCerts(t)
	proxyAddr, stop := startProxy(t, upstreamAddr, certs, &fakePolicy{}, &memoryRecorder{}, nil)
	defer stop()

	frontend, conn, _ := connectDirectTLSFrontend(t, proxyAddr, certs)
	defer conn.Close()

	frontend.Send(&pgproto3.Query{String: "select 1"})
	require.NoError(t, frontend.Flush())
	var sawRow bool
	for {
		msg, err := frontend.Receive()
		require.NoError(t, err)
		switch m := msg.(type) {
		case *pgproto3.DataRow:
			require.Len(t, m.Values, 1)
			require.Equal(t, "1", string(m.Values[0]))
			sawRow = true
		case *pgproto3.ErrorResponse:
			t.Fatalf("unexpected postgres error: %s: %s", m.Code, m.Message)
		case *pgproto3.ReadyForQuery:
			require.True(t, sawRow)
			return
		}
	}
}

func TestProxyExtendedFlushBeforeSyncFailsVisible(t *testing.T) {
	upstreamAddr := startPasswordPostgres(t)
	certs := newTestCerts(t)
	proxyAddr, stop := startProxy(t, upstreamAddr, certs, &fakePolicy{}, &memoryRecorder{}, nil)
	defer stop()

	frontend, conn, _ := connectDirectTLSFrontend(t, proxyAddr, certs)
	defer conn.Close()

	frontend.Send(&pgproto3.Parse{Name: "stmt1", Query: "select 1"})
	frontend.Send(&pgproto3.Bind{DestinationPortal: "portal1", PreparedStatement: "stmt1"})
	frontend.Send(&pgproto3.Execute{Portal: "portal1"})
	frontend.Send(&pgproto3.Flush{})
	require.NoError(t, frontend.Flush())

	errResp := readErrorResponse(t, frontend)
	require.Equal(t, "0A000", errResp.Code)
	require.Contains(t, errResp.Detail, "Flush before Sync")

	frontend.Send(&pgproto3.Sync{})
	require.NoError(t, frontend.Flush())
	errors, _ := readUntilReady(t, frontend)
	require.Empty(t, errors)
	requireFrontendSimpleQuery(t, frontend, "select 1", "1")
}

func TestProxyExtendedMultipleExecuteBeforeSyncFailsVisible(t *testing.T) {
	upstreamAddr := startPasswordPostgres(t)
	certs := newTestCerts(t)
	proxyAddr, stop := startProxy(t, upstreamAddr, certs, &fakePolicy{}, &memoryRecorder{}, nil)
	defer stop()

	frontend, conn, _ := connectDirectTLSFrontend(t, proxyAddr, certs)
	defer conn.Close()

	frontend.Send(&pgproto3.Parse{Name: "stmt1", Query: "select 1"})
	frontend.Send(&pgproto3.Bind{DestinationPortal: "portal1", PreparedStatement: "stmt1"})
	frontend.Send(&pgproto3.Execute{Portal: "portal1"})
	frontend.Send(&pgproto3.Execute{Portal: "portal1"})
	frontend.Send(&pgproto3.Sync{})
	require.NoError(t, frontend.Flush())

	errors, _ := readUntilReady(t, frontend)
	require.Len(t, errors, 1)
	require.Equal(t, "0A000", errors[0].Code)
	require.Contains(t, errors[0].Detail, "multiple extended Execute")

	requireFrontendSimpleQuery(t, frontend, "select 1", "1")
}

func TestProxyExtendedMessageAfterExecuteBeforeSyncFailsVisible(t *testing.T) {
	upstreamAddr := startPasswordPostgres(t)
	certs := newTestCerts(t)
	rec := &memoryRecorder{}
	proxyAddr, stop := startProxy(t, upstreamAddr, certs, &fakePolicy{}, rec, nil)
	defer stop()

	frontend, conn, _ := connectDirectTLSFrontend(t, proxyAddr, certs)
	defer conn.Close()

	frontend.Send(&pgproto3.Parse{Name: "stmt1", Query: "select 1"})
	frontend.Send(&pgproto3.Bind{DestinationPortal: "portal1", PreparedStatement: "stmt1"})
	frontend.Send(&pgproto3.Execute{Portal: "portal1"})
	frontend.Send(&pgproto3.Parse{Name: "bad", Query: "select from"})
	frontend.Send(&pgproto3.Sync{})
	require.NoError(t, frontend.Flush())

	errors, _ := readUntilReady(t, frontend)
	require.Len(t, errors, 1)
	require.Equal(t, "0A000", errors[0].Code)
	require.Contains(t, errors[0].Detail, "messages after Execute")
	require.Empty(t, rec.records())

	requireFrontendSimpleQuery(t, frontend, "select 1", "1")
}

func TestProxyExtendedRowCapRejectsChunkedPortalExecution(t *testing.T) {
	upstreamAddr := startPasswordPostgres(t)
	certs := newTestCerts(t)
	policy := &fakePolicy{
		query: func(_ context.Context, req QueryRequest) (*Decision, error) {
			if req.StatementClass == "SELECT" {
				return &Decision{Action: DecisionRowCap, RowCap: 2}, nil
			}
			return &Decision{Action: DecisionAllow}, nil
		},
	}
	proxyAddr, stop := startProxy(t, upstreamAddr, certs, policy, &memoryRecorder{}, nil)
	defer stop()

	frontend, conn, _ := connectDirectTLSFrontend(t, proxyAddr, certs)
	defer conn.Close()

	frontend.Send(&pgproto3.Parse{Name: "stmt", Query: "select generate_series(1, 5)"})
	frontend.Send(&pgproto3.Bind{DestinationPortal: "portal", PreparedStatement: "stmt"})
	frontend.Send(&pgproto3.Execute{Portal: "portal", MaxRows: 1})
	frontend.Send(&pgproto3.Sync{})
	require.NoError(t, frontend.Flush())

	errors, _ := readUntilReady(t, frontend)
	require.Len(t, errors, 1)
	require.Equal(t, "0A000", errors[0].Code)
	require.Contains(t, errors[0].Detail, "row-capped extended Execute")

	requireFrontendSimpleQuery(t, frontend, "select 1", "1")
}

func TestProxyCancelRequestForwarded(t *testing.T) {
	upstreamAddr := startPasswordPostgres(t)
	certs := newTestCerts(t)
	rec := &memoryRecorder{}
	proxyAddr, stop := startProxy(t, upstreamAddr, certs, &fakePolicy{}, rec, nil)
	defer stop()

	frontend, conn, key := connectDirectTLSFrontend(t, proxyAddr, certs)
	defer conn.Close()

	frontend.Send(&pgproto3.Query{String: "select pg_sleep(10)"})
	require.NoError(t, frontend.Flush())
	done := make(chan error, 1)
	go func() {
		var sawCancel bool
		for {
			msg, err := frontend.Receive()
			if err != nil {
				done <- err
				return
			}
			switch m := msg.(type) {
			case *pgproto3.ErrorResponse:
				if m.Code == "57014" {
					sawCancel = true
				}
			case *pgproto3.ReadyForQuery:
				if !sawCancel {
					done <- errors.New("query completed without cancellation")
					return
				}
				done <- nil
				return
			}
		}
	}()

	time.Sleep(200 * time.Millisecond)
	sendCancelRequest(t, proxyAddr, key)

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("cancel request did not interrupt the active query")
	}

	records := rec.records()
	require.Len(t, records, 1)
	require.Equal(t, "error", records[0].Status)
	require.Equal(t, "57014", records[0].ErrorCode)
}

func TestStartPostgresTLSForCancelNegotiatesSSLRequest(t *testing.T) {
	certs := newTestCerts(t)
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	errCh := make(chan error, 1)
	cancelCh := make(chan *pgproto3.CancelRequest, 1)
	go func() {
		backend := pgproto3.NewBackend(serverConn, serverConn)
		msg, err := backend.ReceiveStartupMessage()
		if err != nil {
			errCh <- err
			return
		}
		if _, ok := msg.(*pgproto3.SSLRequest); !ok {
			errCh <- fmt.Errorf("expected SSLRequest, got %T", msg)
			return
		}
		if _, err := serverConn.Write([]byte{'S'}); err != nil {
			errCh <- err
			return
		}
		tlsConn := tls.Server(serverConn, &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{certs.serverCert},
		})
		if err := tlsConn.Handshake(); err != nil {
			errCh <- err
			return
		}
		tlsBackend := pgproto3.NewBackend(tlsConn, tlsConn)
		msg, err = tlsBackend.ReceiveStartupMessage()
		if err != nil {
			errCh <- err
			return
		}
		cancel, ok := msg.(*pgproto3.CancelRequest)
		if !ok {
			errCh <- fmt.Errorf("expected CancelRequest, got %T", msg)
			return
		}
		cancelCh <- cancel
		errCh <- nil
	}()

	tlsConn, err := startPostgresTLSForCancel(t.Context(), clientConn, &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    certs.clientPool,
		ServerName: "localhost",
	})
	require.NoError(t, err)
	buf, err := (&pgproto3.CancelRequest{ProcessID: 1234, SecretKey: []byte{1, 2, 3, 4}}).Encode(nil)
	require.NoError(t, err)
	_, err = tlsConn.Write(buf)
	require.NoError(t, err)

	select {
	case cancel := <-cancelCh:
		require.Equal(t, uint32(1234), cancel.ProcessID)
		require.Equal(t, []byte{1, 2, 3, 4}, cancel.SecretKey)
	case <-time.After(5 * time.Second):
		t.Fatal("server did not receive cancel request over TLS")
	}
	require.NoError(t, <-errCh)
}

func TestProxyCopyFromStdinFailsClosedUntilSQLParserLands(t *testing.T) {
	upstreamAddr := startPasswordPostgres(t)
	execUpstream(t, upstreamAddr, "create table copy_target (n int)")
	certs := newTestCerts(t)
	rec := &memoryRecorder{}
	proxyAddr, stop := startProxy(t, upstreamAddr, certs, &fakePolicy{}, rec, nil)
	defer stop()

	conn := connectPGX(t, proxyAddr, certs, pgx.QueryExecModeSimpleProtocol)
	defer conn.Close(context.Background())

	_, err := conn.Exec(context.Background(), "copy copy_target from stdin")
	require.Error(t, err)
	require.Contains(t, strings.ToLower(err.Error()), "postgres query denied")

	records := rec.records()
	require.Len(t, records, 1)
	require.Equal(t, "COPY", records[0].StatementClass)
	require.Equal(t, DecisionDeny, records[0].Decision)
	require.Equal(t, "denied", records[0].Status)
	require.Equal(t, "42501", records[0].ErrorCode)
	require.Contains(t, records[0].Reason, "SQL parser support")
}

func TestProxyCopyToStdoutFailsClosedUntilSQLParserLands(t *testing.T) {
	upstreamAddr := startPasswordPostgres(t)
	certs := newTestCerts(t)
	rec := &memoryRecorder{}
	policy := &fakePolicy{
		query: func(_ context.Context, req QueryRequest) (*Decision, error) {
			if req.StatementClass == "COPY" {
				return &Decision{Action: DecisionRowCap, RowCap: 1}, nil
			}
			return &Decision{Action: DecisionAllow}, nil
		},
	}
	proxyAddr, stop := startProxy(t, upstreamAddr, certs, policy, rec, nil)
	defer stop()

	conn := connectPGX(t, proxyAddr, certs, pgx.QueryExecModeSimpleProtocol)
	defer conn.Close(context.Background())

	_, err := conn.Exec(context.Background(), "copy (select generate_series(1, 5)) to stdout")
	require.Error(t, err)
	require.Contains(t, strings.ToLower(err.Error()), "postgres query denied")

	records := rec.records()
	require.Len(t, records, 1)
	require.Equal(t, "COPY", records[0].StatementClass)
	require.Equal(t, DecisionDeny, records[0].Decision)
	require.Equal(t, "denied", records[0].Status)
	require.Equal(t, "42501", records[0].ErrorCode)
	require.Contains(t, records[0].Reason, "SQL parser support")
}

func TestProxyWrapperStatementsFailClosedUntilSQLParserLands(t *testing.T) {
	upstreamAddr := startPasswordPostgres(t)
	certs := newTestCerts(t)
	rec := &memoryRecorder{}
	proxyAddr, stop := startProxy(t, upstreamAddr, certs, &fakePolicy{}, rec, nil)
	defer stop()

	conn := connectPGX(t, proxyAddr, certs, pgx.QueryExecModeSimpleProtocol)
	defer conn.Close(context.Background())

	_, err := conn.Exec(context.Background(), "explain analyze delete from blocked_target")
	require.Error(t, err)
	_, err = conn.Exec(context.Background(), "with deleted as (delete from blocked_target returning *) select * from deleted")
	require.Error(t, err)
	_, err = conn.Exec(context.Background(), "do $$ begin drop table blocked_target; end $$")
	require.Error(t, err)
	_, err = conn.Exec(context.Background(), "call blocked_target()")
	require.Error(t, err)
	_, err = conn.Exec(context.Background(), "create table blocked_target (id int)")
	require.Error(t, err)
	_, err = conn.Exec(context.Background(), "prepare blocked_target as delete from sensitive_rows")
	require.Error(t, err)
	_, err = conn.Exec(context.Background(), "execute blocked_target")
	require.Error(t, err)
	_, err = conn.Exec(context.Background(), "copy sensitive_rows to stdout")
	require.Error(t, err)
	_, err = conn.Exec(context.Background(), "merge into sensitive_rows t using (values ('x')) s(secret_text) on false when not matched then insert values (s.secret_text)")
	require.Error(t, err)
	_, err = conn.Exec(context.Background(), "select 1 into blocked_target")
	require.Error(t, err)
	_, err = conn.Exec(context.Background(), "select * from blocked_target for update")
	require.Error(t, err)
	_, err = conn.Exec(context.Background(), longSelectIntoSQL())
	require.Error(t, err)
	_, err = conn.Exec(context.Background(), longSelectForUpdateSQL())
	require.Error(t, err)
	_, err = conn.Exec(context.Background(), "deallocate all")
	require.Error(t, err)
	_, err = conn.Exec(context.Background(), "discard all")
	require.Error(t, err)
	_, err = conn.Exec(context.Background(), "set role administrator")
	require.Error(t, err)
	_, err = conn.Exec(context.Background(), "set local role administrator")
	require.Error(t, err)
	_, err = conn.Exec(context.Background(), "set session role administrator")
	require.Error(t, err)
	_, err = conn.Exec(context.Background(), "set session authorization administrator")
	require.Error(t, err)
	_, err = conn.Exec(context.Background(), "set local session authorization administrator")
	require.Error(t, err)
	_, err = conn.Exec(context.Background(), "set session_authorization = 'administrator'")
	require.Error(t, err)
	_, err = conn.Exec(context.Background(), "reset role")
	require.Error(t, err)
	_, err = conn.Exec(context.Background(), "reset session authorization")
	require.Error(t, err)
	_, err = conn.Exec(context.Background(), "reset all")
	require.Error(t, err)

	records := rec.records()
	require.Len(t, records, 24)
	for i, statementClass := range []string{"EXPLAIN", "WITH", "DO", "CALL", "CREATE", "PREPARE", "EXECUTE", "COPY", "MERGE", "SELECT_INTO", "SELECT_FOR_LOCK", "SELECT_INTO", "SELECT_FOR_LOCK", "DEALLOCATE", "DISCARD", "SET_ROLE", "SET_ROLE", "SET_ROLE", "SET_SESSION_AUTHORIZATION", "SET_SESSION_AUTHORIZATION", "SET_SESSION_AUTHORIZATION", "RESET_ROLE", "RESET_SESSION_AUTHORIZATION", "RESET_ALL"} {
		require.Equal(t, statementClass, records[i].StatementClass)
		require.Equal(t, DecisionDeny, records[i].Decision)
		require.Contains(t, records[i].Reason, "SQL parser support")
	}
}

func TestProxyExtendedWrapperStatementsFailClosedUntilSQLParserLands(t *testing.T) {
	upstreamAddr := startPasswordPostgres(t)
	certs := newTestCerts(t)
	rec := &memoryRecorder{}
	proxyAddr, stop := startProxy(t, upstreamAddr, certs, &fakePolicy{}, rec, nil)
	defer stop()

	conn := connectPGX(t, proxyAddr, certs, pgx.QueryExecModeCacheStatement)
	defer conn.Close(context.Background())

	_, err := conn.Exec(context.Background(), longSelectIntoSQL())
	require.Error(t, err)
	_, err = conn.Exec(context.Background(), "deallocate all")
	require.Error(t, err)
	_, err = conn.Exec(context.Background(), "discard all")
	require.Error(t, err)
	_, err = conn.Exec(context.Background(), "set role administrator")
	require.Error(t, err)

	var n int
	require.NoError(t, conn.QueryRow(context.Background(), "select $1::int", 1).Scan(&n))
	require.Equal(t, 1, n)

	records := rec.records()
	require.Len(t, records, 5)
	require.Equal(t, "SELECT_INTO", records[0].StatementClass)
	require.Equal(t, DecisionDeny, records[0].Decision)
	require.Contains(t, records[0].Reason, "SQL parser support")
	require.Equal(t, "DEALLOCATE", records[1].StatementClass)
	require.Equal(t, DecisionDeny, records[1].Decision)
	require.Contains(t, records[1].Reason, "SQL parser support")
	require.Equal(t, "DISCARD", records[2].StatementClass)
	require.Equal(t, DecisionDeny, records[2].Decision)
	require.Contains(t, records[2].Reason, "SQL parser support")
	require.Equal(t, "SET_ROLE", records[3].StatementClass)
	require.Equal(t, DecisionDeny, records[3].Decision)
	require.Contains(t, records[3].Reason, "SQL parser support")
	require.Equal(t, DecisionAllow, records[4].Decision)
	require.Equal(t, "SELECT", records[4].StatementClass)
}

func TestProxyExtendedParserRequiredStatementDoesNotCallPolicy(t *testing.T) {
	upstreamAddr := startPasswordPostgres(t)
	certs := newTestCerts(t)
	rec := &memoryRecorder{}
	var policyCalls atomic.Int32
	policy := &fakePolicy{
		query: func(context.Context, QueryRequest) (*Decision, error) {
			policyCalls.Add(1)
			return &Decision{Action: DecisionAllow}, nil
		},
	}
	proxyAddr, stop := startProxy(t, upstreamAddr, certs, policy, rec, nil)
	defer stop()

	conn := connectPGX(t, proxyAddr, certs, pgx.QueryExecModeCacheStatement)
	defer conn.Close(context.Background())

	_, err := conn.Exec(context.Background(), longSelectIntoSQL())
	require.Error(t, err)
	require.Equal(t, int32(0), policyCalls.Load())

	records := rec.records()
	require.Len(t, records, 1)
	require.Equal(t, "SELECT_INTO", records[0].StatementClass)
	require.Equal(t, DecisionDeny, records[0].Decision)
}

func TestProxyExtendedReauthBeforeExecute(t *testing.T) {
	upstreamAddr := startPasswordPostgres(t)
	certs := newTestCerts(t)
	var revoked atomic.Bool
	proxyAddr, stop := startProxy(t, upstreamAddr, certs, &fakePolicy{}, &memoryRecorder{}, &revoked)
	defer stop()

	frontend, conn, _ := connectDirectTLSFrontend(t, proxyAddr, certs)
	defer conn.Close()

	frontend.Send(&pgproto3.Parse{Name: "stmt", Query: "select 1"})
	frontend.Send(&pgproto3.Bind{DestinationPortal: "portal", PreparedStatement: "stmt"})
	require.NoError(t, frontend.Flush())
	time.Sleep(100 * time.Millisecond)
	revoked.Store(true)
	frontend.Send(&pgproto3.Execute{Portal: "portal"})
	frontend.Send(&pgproto3.Sync{})
	require.NoError(t, frontend.Flush())

	errors, _ := readUntilReady(t, frontend)
	require.Len(t, errors, 1)
	require.Equal(t, "42501", errors[0].Code)
}

func TestProxyExtendedExecuteFirstCycleReauthRevokesBeforeUpstream(t *testing.T) {
	upstreamAddr := startPasswordPostgres(t)
	certs := newTestCerts(t)
	var revoked atomic.Bool
	proxyAddr, stop := startProxy(t, upstreamAddr, certs, &fakePolicy{}, &memoryRecorder{}, &revoked)
	defer stop()

	frontend, conn, _ := connectDirectTLSFrontend(t, proxyAddr, certs)
	defer conn.Close()

	frontend.Send(&pgproto3.Query{String: "begin"})
	require.NoError(t, frontend.Flush())
	errors, txStatus := readUntilReady(t, frontend)
	require.Empty(t, errors)
	require.Equal(t, byte('T'), txStatus)

	frontend.Send(&pgproto3.Parse{Name: "stmt", Query: "select 1"})
	frontend.Send(&pgproto3.Bind{DestinationPortal: "portal", PreparedStatement: "stmt"})
	frontend.Send(&pgproto3.Sync{})
	require.NoError(t, frontend.Flush())
	result := readMessagesUntilReady(t, frontend)
	require.Empty(t, result.errors)
	require.Equal(t, byte('T'), result.txStatus)

	revoked.Store(true)
	frontend.Send(&pgproto3.Execute{Portal: "portal"})
	frontend.Send(&pgproto3.Sync{})
	require.NoError(t, frontend.Flush())

	result = readMessagesUntilReady(t, frontend)
	require.Equal(t, []string{
		"ErrorResponse",
		"ReadyForQuery",
	}, result.types)
	require.Len(t, result.errors, 1)
	require.Equal(t, "42501", result.errors[0].Code)
	require.Empty(t, result.values)
}

func TestExtendedBatchMessageCountLimitIsDockerIndependent(t *testing.T) {
	state := extendedCycleState{
		session:           &Session{ID: "session-1"},
		started:           time.Now(),
		statements:        map[string]preparedStatement{},
		portals:           map[string]portalState{},
		pendingStatements: map[string]*preparedStatement{},
		pendingPortals:    map[string]*portalState{},
		failedResponseOp:  -1,
	}
	server := &Server{}

	for i := 0; i < maxExtendedBatchMessages; i++ {
		err := server.appendExtendedMessage(t.Context(), &state, &pgproto3.Parse{
			Name:  fmt.Sprintf("stmt_%d", i),
			Query: "select 1",
		})
		require.NoError(t, err)
	}

	err := server.appendExtendedMessage(t.Context(), &state, &pgproto3.Parse{
		Name:  "stmt_over_limit",
		Query: "select 1",
	})
	require.ErrorIs(t, err, errExtendedBatchLimitExceeded)
}

func TestProxyDoesNotMutateUpstreamCredentialPointer(t *testing.T) {
	upstreamAddr := startPasswordPostgres(t)
	certs := newTestCerts(t)
	identity := &fakeIdentity{
		upstream: UpstreamCredentials{
			Password: "pomeriumtest",
		},
	}
	proxyAddr, stop := startProxyWithIdentity(t, upstreamAddr, certs, identity, &fakePolicy{}, &memoryRecorder{})
	defer stop()

	conn, err := connectPGXWithOptions(t, proxyAddr, certs, pgx.QueryExecModeSimpleProtocol, "pomeriumtest", true)
	require.NoError(t, err)
	defer conn.Close(context.Background())

	var n int
	require.NoError(t, conn.QueryRow(context.Background(), "select 1").Scan(&n))
	require.Empty(t, identity.upstream.Username)
	require.Empty(t, identity.upstream.Database)
}

func TestConnectUpstreamDoesNotDialPGEnvFallback(t *testing.T) {
	envAddr, captured := startPlaintextPostgresCredentialTrap(t)
	envHost, envPort, err := net.SplitHostPort(envAddr)
	require.NoError(t, err)
	t.Setenv("PGHOST", envHost)
	t.Setenv("PGPORT", envPort)
	t.Setenv("PGSSLMODE", "prefer")
	t.Setenv("PGTARGETSESSIONATTRS", "read-write")
	t.Setenv("PGOPTIONS", "-c search_path=env_schema")
	t.Setenv("PGAPPNAME", "env-app")

	deadPrimary, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	deadPrimaryAddr := deadPrimary.Addr().String()
	require.NoError(t, deadPrimary.Close())

	server := &Server{
		UpstreamAddr: deadPrimaryAddr,
		Identity: &fakeIdentity{
			upstream: UpstreamCredentials{
				Username: "route_user",
				Password: "route_password",
				Database: "route_db",
			},
		},
	}
	var clientOut bytes.Buffer
	client := pgproto3.NewBackend(bytes.NewReader(nil), &clientOut)
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()

	_, _, _, err = server.connectUpstream(ctx, &Session{
		Database:        "route_db",
		DatabaseUser:    "route_user",
		ApplicationName: "route-app",
	}, pgproto3.ProtocolVersion30, client)
	require.Error(t, err)

	select {
	case leaked := <-captured:
		t.Fatalf("postgres proxy dialed PGHOST fallback and exposed plaintext startup/auth bytes: %q", string(leaked))
	case <-time.After(200 * time.Millisecond):
	}
}

func TestProxyRowCapFailsVisibly(t *testing.T) {
	upstreamAddr := startPasswordPostgres(t)
	certs := newTestCerts(t)
	rec := &memoryRecorder{}
	policy := &fakePolicy{
		query: func(_ context.Context, req QueryRequest) (*Decision, error) {
			if req.StatementClass == "SELECT" {
				return &Decision{Action: DecisionRowCap, RowCap: 2, Reason: "small result only"}, nil
			}
			return &Decision{Action: DecisionAllow}, nil
		},
	}
	proxyAddr, stop := startProxy(t, upstreamAddr, certs, policy, rec, nil)
	defer stop()

	conn := connectPGX(t, proxyAddr, certs, pgx.QueryExecModeSimpleProtocol)
	defer conn.Close(context.Background())

	rows, err := conn.Query(context.Background(), "select generate_series(1, 5)")
	require.NoError(t, err)
	var seen []int
	for rows.Next() {
		var n int
		require.NoError(t, rows.Scan(&n))
		seen = append(seen, n)
	}
	require.Error(t, rows.Err())
	require.LessOrEqual(t, len(seen), 2)

	records := rec.records()
	require.Len(t, records, 1)
	require.Equal(t, DecisionRowCap, records[0].Decision)
	require.Equal(t, "row_cap_exceeded", records[0].Status)
	require.Equal(t, "P0001", records[0].ErrorCode)
}

func TestProxyRowCapNonSelectFailsClosed(t *testing.T) {
	upstreamAddr := startPasswordPostgres(t)
	certs := newTestCerts(t)
	rec := &memoryRecorder{}
	policy := &fakePolicy{
		query: func(_ context.Context, req QueryRequest) (*Decision, error) {
			if req.StatementClass == "UPDATE" {
				return &Decision{Action: DecisionRowCap, RowCap: 1}, nil
			}
			return &Decision{Action: DecisionAllow}, nil
		},
	}
	proxyAddr, stop := startProxy(t, upstreamAddr, certs, policy, rec, nil)
	defer stop()

	conn := connectPGX(t, proxyAddr, certs, pgx.QueryExecModeSimpleProtocol)
	defer conn.Close(context.Background())

	_, err := conn.Exec(context.Background(), "update pg_settings set setting = setting where false")
	require.Error(t, err)
	require.Contains(t, strings.ToLower(err.Error()), "postgres query denied")

	records := rec.records()
	require.Len(t, records, 1)
	require.Equal(t, "UPDATE", records[0].StatementClass)
	require.Equal(t, DecisionDeny, records[0].Decision)
	require.Contains(t, records[0].Reason, "row caps are only supported for SELECT")
}

func TestProxyLiveRevocation(t *testing.T) {
	upstreamAddr := startPasswordPostgres(t)
	certs := newTestCerts(t)
	rec := &memoryRecorder{}
	var revoked atomic.Bool
	proxyAddr, stop := startProxy(t, upstreamAddr, certs, &fakePolicy{}, rec, &revoked)
	defer stop()

	conn := connectPGX(t, proxyAddr, certs, pgx.QueryExecModeSimpleProtocol)
	defer conn.Close(context.Background())

	var n int
	require.NoError(t, conn.QueryRow(context.Background(), "select 1").Scan(&n))
	revoked.Store(true)
	_, err := conn.Exec(context.Background(), "select 2")
	require.Errorf(t, err, "expected active session revocation to fail the next query; records=%+v revoked=%t", rec.records(), revoked.Load())
}

func TestProxyPeriodicRevocationClosesActiveQuery(t *testing.T) {
	upstreamAddr := startPasswordPostgres(t)
	certs := newTestCerts(t)
	rec := &memoryRecorder{}
	var revoked atomic.Bool
	proxyAddr, stop := startProxyWithOptions(t, upstreamAddr, certs, &fakePolicy{}, rec, &revoked, func(server *Server) {
		server.ReauthorizeInterval = 50 * time.Millisecond
	})
	defer stop()

	conn := connectPGX(t, proxyAddr, certs, pgx.QueryExecModeSimpleProtocol)
	defer conn.Close(context.Background())

	execCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	started := time.Now()
	go func() {
		_, err := conn.Exec(execCtx, "select pg_sleep(10)")
		done <- err
	}()

	time.Sleep(200 * time.Millisecond)
	revoked.Store(true)

	select {
	case err := <-done:
		require.Error(t, err)
		require.Less(t, time.Since(started), 3*time.Second)
	case <-time.After(5 * time.Second):
		t.Fatal("active query was not closed after revocation")
	}
}

func startPlaintextPostgresCredentialTrap(t *testing.T) (string, <-chan []byte) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	captured := make(chan []byte, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

		var payload bytes.Buffer
		startup, err := readPostgresStartupPacket(conn)
		if err != nil {
			return
		}
		payload.Write(startup)
		_, _ = conn.Write([]byte{'R', 0, 0, 0, 8, 0, 0, 0, 3})
		password, err := readPostgresTypedMessage(conn)
		if err == nil {
			payload.Write(password)
		}
		captured <- payload.Bytes()
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("postgres credential trap did not stop")
		}
	})
	return ln.Addr().String(), captured
}

func readPostgresStartupPacket(r io.Reader) ([]byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, err
	}
	bodyLen := int(binary.BigEndian.Uint32(header[:])) - 4
	if bodyLen < 0 || bodyLen > maxPostgresMessageBodyLen {
		return nil, fmt.Errorf("invalid startup body length %d", bodyLen)
	}
	body := make([]byte, bodyLen)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	return append(header[:], body...), nil
}

func readPostgresTypedMessage(r io.Reader) ([]byte, error) {
	var header [5]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, err
	}
	bodyLen := int(binary.BigEndian.Uint32(header[1:])) - 4
	if bodyLen < 0 || bodyLen > maxPostgresMessageBodyLen {
		return nil, fmt.Errorf("invalid message body length %d", bodyLen)
	}
	body := make([]byte, bodyLen)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	return append(header[:], body...), nil
}

func startPasswordPostgres(t *testing.T) string {
	t.Helper()
	testcontainers.SkipIfProviderIsNotHealthy(t)
	ctx := oteltrace.ContextWithSpan(t.Context(), trace.ValidNoopSpan{})
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
	waitForPasswordPostgres(t, addr)
	return addr
}

func waitForPasswordPostgres(t *testing.T, addr string) {
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

func execUpstream(t *testing.T, addr string, sql string) {
	t.Helper()
	dsn := fmt.Sprintf("postgres://pomeriumtest:pomeriumtest@%s/pomeriumtest?sslmode=disable", addr)
	conn, err := pgx.Connect(context.Background(), dsn)
	require.NoError(t, err)
	defer conn.Close(context.Background())
	_, err = conn.Exec(context.Background(), sql)
	require.NoError(t, err)
}

func requireUpstreamTableExists(t *testing.T, addr string, table string) {
	t.Helper()
	dsn := fmt.Sprintf("postgres://pomeriumtest:pomeriumtest@%s/pomeriumtest?sslmode=disable", addr)
	conn, err := pgx.Connect(context.Background(), dsn)
	require.NoError(t, err)
	defer conn.Close(context.Background())
	var exists bool
	err = conn.QueryRow(context.Background(), "select to_regclass($1) is not null", table).Scan(&exists)
	require.NoError(t, err)
	require.True(t, exists, "expected upstream table %q to exist", table)
}

func requireUpstreamTableCount(t *testing.T, addr string, table string, want int) {
	t.Helper()
	dsn := fmt.Sprintf("postgres://pomeriumtest:pomeriumtest@%s/pomeriumtest?sslmode=disable", addr)
	conn, err := pgx.Connect(context.Background(), dsn)
	require.NoError(t, err)
	defer conn.Close(context.Background())
	var got int
	err = conn.QueryRow(context.Background(), fmt.Sprintf("select count(*) from %s", table)).Scan(&got)
	require.NoError(t, err)
	require.Equal(t, want, got, "unexpected upstream row count for %q", table)
}

func startProxy(t *testing.T, upstreamAddr string, certs testCerts, policy Policy, rec Recorder, revoked *atomic.Bool) (string, func()) {
	t.Helper()
	return startProxyWithOptions(t, upstreamAddr, certs, policy, rec, revoked, nil)
}

func startProxyWithOptions(t *testing.T, upstreamAddr string, certs testCerts, policy Policy, rec Recorder, revoked *atomic.Bool, configure func(*Server)) (string, func()) {
	t.Helper()
	return startProxyWithIdentityAndOptions(t, upstreamAddr, certs, &fakeIdentity{
		upstream: UpstreamCredentials{
			Username: "pomeriumtest",
			Password: "pomeriumtest",
			Database: "pomeriumtest",
		},
		revoked: revoked,
	}, policy, rec, configure)
}

func startProxyWithIdentity(t *testing.T, upstreamAddr string, certs testCerts, identity Identity, policy Policy, rec Recorder) (string, func()) {
	t.Helper()
	return startProxyWithIdentityAndOptions(t, upstreamAddr, certs, identity, policy, rec, nil)
}

func startProxyWithIdentityAndOptions(t *testing.T, upstreamAddr string, certs testCerts, identity Identity, policy Policy, rec Recorder, configure func(*Server)) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	server := &Server{
		UpstreamAddr: upstreamAddr,
		DownstreamTLS: &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{certs.serverCert},
			ClientCAs:    certs.clientPool,
			ClientAuth:   tls.RequireAndVerifyClientCert,
		},
		Identity: identity,
		Policy:   policy,
		Recorder: rec,
	}
	if configure != nil {
		configure(server)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		err := server.Serve(ctx, ln)
		if errors.Is(err, context.Canceled) {
			err = nil
		}
		done <- err
	}()
	return ln.Addr().String(), func() {
		cancel()
		_ = ln.Close()
		select {
		case err := <-done:
			require.NoError(t, err)
		case <-time.After(5 * time.Second):
			t.Fatal("postgres proxy did not stop")
		}
	}
}

func connectPGX(t *testing.T, addr string, certs testCerts, mode pgx.QueryExecMode) *pgx.Conn {
	t.Helper()
	conn, err := connectPGXWithOptions(t, addr, certs, mode, "alice", true)
	require.NoError(t, err)
	return conn
}

func connectPGXWithOptions(t *testing.T, addr string, certs testCerts, mode pgx.QueryExecMode, user string, includeClientCert bool) (*pgx.Conn, error) {
	t.Helper()
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	if host == "127.0.0.1" {
		host = "localhost"
	}
	dsn := fmt.Sprintf(
		"host=%s port=%s user=%s dbname=pomeriumtest application_name=postgresproxy-test sslmode=verify-full sslrootcert=%s gssencmode=disable",
		host, port, user, certs.caPath,
	)
	if includeClientCert {
		dsn += fmt.Sprintf(" sslcert=%s sslkey=%s", certs.clientCertPath, certs.clientKeyPath)
	}
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}
	cfg.DefaultQueryExecMode = mode
	return pgx.ConnectConfig(context.Background(), cfg)
}

func connectDirectTLSFrontend(t *testing.T, addr string, certs testCerts) (*pgproto3.Frontend, net.Conn, pgproto3.BackendKeyData) {
	t.Helper()
	raw, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = raw.Close()
	})
	conn := tls.Client(raw, &tls.Config{
		MinVersion:   tls.VersionTLS12,
		ServerName:   "localhost",
		RootCAs:      certs.clientPool,
		Certificates: []tls.Certificate{certs.clientCert},
	})
	require.NoError(t, conn.Handshake())
	frontend := pgproto3.NewFrontend(conn, conn)
	frontend.Send(&pgproto3.StartupMessage{
		ProtocolVersion: pgproto3.ProtocolVersion30,
		Parameters: map[string]string{
			"user":             "alice",
			"database":         "pomeriumtest",
			"application_name": "postgresproxy-direct-tls-test",
		},
	})
	require.NoError(t, frontend.Flush())
	var key pgproto3.BackendKeyData
	for {
		msg, err := frontend.Receive()
		require.NoError(t, err)
		switch m := msg.(type) {
		case *pgproto3.AuthenticationOk, *pgproto3.ParameterStatus:
		case *pgproto3.BackendKeyData:
			key = *m
		case *pgproto3.ErrorResponse:
			t.Fatalf("startup failed: %s: %s", m.Code, m.Message)
		case *pgproto3.ReadyForQuery:
			require.NotZero(t, key.ProcessID)
			require.Len(t, key.SecretKey, 4)
			return frontend, conn, key
		}
	}
}

func sendCancelRequest(t *testing.T, addr string, key pgproto3.BackendKeyData) {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	defer conn.Close()
	buf, err := (&pgproto3.CancelRequest{ProcessID: key.ProcessID, SecretKey: key.SecretKey}).Encode(nil)
	require.NoError(t, err)
	_, err = conn.Write(buf)
	require.NoError(t, err)
}

func readUntilReady(t *testing.T, frontend *pgproto3.Frontend) ([]*pgproto3.ErrorResponse, byte) {
	t.Helper()
	var errors []*pgproto3.ErrorResponse
	for {
		msg, err := frontend.Receive()
		require.NoError(t, err)
		switch m := msg.(type) {
		case *pgproto3.ErrorResponse:
			errors = append(errors, m)
		case *pgproto3.ReadyForQuery:
			return errors, m.TxStatus
		}
	}
}

type frontendReadResult struct {
	types    []string
	values   []string
	errors   []*pgproto3.ErrorResponse
	txStatus byte
}

func readMessagesUntilReady(t *testing.T, frontend *pgproto3.Frontend) frontendReadResult {
	t.Helper()
	var result frontendReadResult
	for {
		msg, err := frontend.Receive()
		require.NoError(t, err)
		result.types = append(result.types, strings.TrimPrefix(fmt.Sprintf("%T", msg), "*pgproto3."))
		switch m := msg.(type) {
		case *pgproto3.DataRow:
			// These helpers are only for the one-column protocol tests in this file.
			require.Len(t, m.Values, 1)
			result.values = append(result.values, string(m.Values[0]))
		case *pgproto3.ErrorResponse:
			result.errors = append(result.errors, m)
		case *pgproto3.ReadyForQuery:
			result.txStatus = m.TxStatus
			return result
		}
	}
}

func readRowsUntilReady(t *testing.T, frontend *pgproto3.Frontend) []string {
	t.Helper()
	result := readMessagesUntilReady(t, frontend)
	if len(result.errors) > 0 {
		errResp := result.errors[0]
		t.Fatalf("unexpected postgres error while reading rows: %s: %s", errResp.Code, errResp.Message)
	}
	return result.values
}

func readErrorResponse(t *testing.T, frontend *pgproto3.Frontend) *pgproto3.ErrorResponse {
	t.Helper()
	msg, err := frontend.Receive()
	require.NoError(t, err)
	errResp, ok := msg.(*pgproto3.ErrorResponse)
	require.Truef(t, ok, "expected ErrorResponse, got %T", msg)
	return errResp
}

func requireFrontendSimpleQuery(t *testing.T, frontend *pgproto3.Frontend, sql string, value string) {
	t.Helper()
	frontend.Send(&pgproto3.Query{String: sql})
	require.NoError(t, frontend.Flush())
	sawRow := false
	for {
		msg, err := frontend.Receive()
		require.NoError(t, err)
		switch m := msg.(type) {
		case *pgproto3.DataRow:
			require.Len(t, m.Values, 1)
			require.Equal(t, value, string(m.Values[0]))
			sawRow = true
		case *pgproto3.ErrorResponse:
			t.Fatalf("unexpected postgres error after recovery: %s: %s", m.Code, m.Message)
		case *pgproto3.ReadyForQuery:
			require.True(t, sawRow, "query returned ready before a row")
			return
		}
	}
}

type fakeIdentity struct {
	upstream    UpstreamCredentials
	revoked     *atomic.Bool
	reauthorize func(context.Context, *Session) error
}

func (f *fakeIdentity) Authenticate(_ context.Context, req AuthRequest) (*Session, error) {
	if req.ClientCertSHA256 == "" {
		return nil, errors.New("client certificate is required")
	}
	return &Session{
		ID:               "session-1",
		UserID:           "user-1",
		RouteID:          "route-1",
		Database:         req.Database,
		DatabaseUser:     req.Username,
		ApplicationName:  req.ApplicationName,
		ClientAddr:       req.ClientAddr.String(),
		ClientCertSHA256: req.ClientCertSHA256,
	}, nil
}

func (f *fakeIdentity) Reauthorize(ctx context.Context, session *Session) error {
	if f.reauthorize != nil {
		return f.reauthorize(ctx, session)
	}
	if f.revoked != nil && f.revoked.Load() {
		return errors.New("session binding revoked")
	}
	return nil
}

func (f *fakeIdentity) UpstreamCredentials(context.Context, *Session) (*UpstreamCredentials, error) {
	return &f.upstream, nil
}

type fakePolicy struct {
	session func(context.Context, *Session) error
	query   func(context.Context, QueryRequest) (*Decision, error)
}

func (f *fakePolicy) AuthorizeSession(ctx context.Context, session *Session) error {
	if f.session != nil {
		return f.session(ctx, session)
	}
	return nil
}

func (f *fakePolicy) AuthorizeQuery(ctx context.Context, req QueryRequest) (*Decision, error) {
	if f.query != nil {
		return f.query(ctx, req)
	}
	return &Decision{Action: DecisionAllow}, nil
}

type memoryRecorder struct {
	mu      sync.Mutex
	queries []QueryRecord
}

func (r *memoryRecorder) BeginSession(context.Context, *Session) error { return nil }

func (r *memoryRecorder) RecordQuery(_ context.Context, q QueryRecord) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.queries = append(r.queries, q)
	return nil
}

func (r *memoryRecorder) EndSession(context.Context, *Session, error) error { return nil }

func (r *memoryRecorder) records() []QueryRecord {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]QueryRecord(nil), r.queries...)
}

type testCerts struct {
	caPath         string
	clientCertPath string
	clientKeyPath  string
	serverCert     tls.Certificate
	clientCert     tls.Certificate
	clientPool     *x509.CertPool
}

func newTestCerts(t *testing.T) testCerts {
	t.Helper()
	dir := t.TempDir()
	caKey := mustRSAKey(t)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "postgresproxy-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	caCert, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)
	caPath := filepath.Join(dir, "ca.pem")
	writePEM(t, caPath, "CERTIFICATE", caDER)

	serverCert := issueCert(t, caCert, caKey, "localhost", []string{"localhost"}, nil, x509.ExtKeyUsageServerAuth)
	clientCert := issueCert(t, caCert, caKey, "alice", nil, nil, x509.ExtKeyUsageClientAuth)
	serverTLS, err := tls.X509KeyPair(serverCert.certPEM, serverCert.keyPEM)
	require.NoError(t, err)
	clientTLS, err := tls.X509KeyPair(clientCert.certPEM, clientCert.keyPEM)
	require.NoError(t, err)
	clientCertPath := filepath.Join(dir, "client.pem")
	clientKeyPath := filepath.Join(dir, "client-key.pem")
	require.NoError(t, os.WriteFile(clientCertPath, clientCert.certPEM, 0o600))
	require.NoError(t, os.WriteFile(clientKeyPath, clientCert.keyPEM, 0o600))

	pool := x509.NewCertPool()
	require.True(t, pool.AppendCertsFromPEM(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})))
	return testCerts{
		caPath:         caPath,
		clientCertPath: clientCertPath,
		clientKeyPath:  clientKeyPath,
		serverCert:     serverTLS,
		clientCert:     clientTLS,
		clientPool:     pool,
	}
}

type issuedCert struct {
	certPEM []byte
	keyPEM  []byte
}

func issueCert(t *testing.T, ca *x509.Certificate, caKey *rsa.PrivateKey, cn string, dnsNames []string, ipAddresses []net.IP, usage x509.ExtKeyUsage) issuedCert {
	t.Helper()
	key := mustRSAKey(t)
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
		IPAddresses:  ipAddresses,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	require.NoError(t, err)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return issuedCert{certPEM: certPEM, keyPEM: keyPEM}
}

func mustRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return key
}

func writePEM(t *testing.T, path, typ string, der []byte) {
	t.Helper()
	require.NoError(t, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600))
}
