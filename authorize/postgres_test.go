package authorize

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/postgresproxy"
	"github.com/pomerium/pomerium/pkg/databrokerutil/testutil"
	configpb "github.com/pomerium/pomerium/pkg/grpc/config"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpc/user"
	"github.com/pomerium/pomerium/pkg/nullable"
)

func TestEvaluatePostgresSessionOmitsSpoofableClientMetadata(t *testing.T) {
	t.Parallel()

	cfg := config.New(config.NewDefaultOptions())
	cfg.Options.Routes = []config.Policy{{
		From: "postgres://db.example.com",
		To:   mustParseWeightedURLs(t, "postgres://postgres.internal:5432"),
		RouteOptions: config.RouteOptions{
			Postgres: nullable.From(config.PostgresRouteSettings{
				AuthenticationMode: nullable.From(configpb.PostgresAuthenticationMode_POSTGRES_AUTHENTICATION_MODE_MANAGED),
				Username:           nullable.From("dbuser"),
				Database:           nullable.From("app"),
				Password:           nullable.From("secret"),
			}),
		},
		SubPolicies: []config.SubPolicy{{
			ID: "postgres-safe-input",
			Rego: []string{`
package pomerium.policy

allow {
	input.postgres.hostname == "db.example.com"
	input.postgres.route_id != ""
	input.postgres.session_binding_id == "BINDING-1"
	object.get(input.postgres, "username", "missing") == "missing"
	object.get(input.postgres, "database", "missing") == "missing"
	object.get(input.postgres, "application_name", "missing") == "missing"
	object.get(input.postgres, "statement_class", "missing") == "missing"
object.get(input.postgres, "query_protocol", "missing") == "missing"
}
`},
		}},
	}}

	a, err := New(t.Context(), cfg)
	require.NoError(t, err)
	attachPostgresTestDatabroker(t, a)

	res, err := a.EvaluatePostgresSession(t.Context(), PostgresRequest{
		Hostname:         "db.example.com",
		SessionID:        "SESSION-1",
		SessionBindingID: "BINDING-1",
		ConfigGeneration: cfg,
	})
	require.NoError(t, err)
	require.True(t, res.Allow.Value)
	require.False(t, res.Deny.Value)
}

func TestPostgresSessionBindingDoesNotImplyValidatedCertificate(t *testing.T) {
	protocolSession := &postgresproxy.Session{
		PomeriumSessionID: "SESSION-1",
		SessionBindingID:  "BINDING-1",
		Hostname:          "db.example.com",
	}
	req := baseEvaluatorRequestFromPostgresRequest(PostgresRequest{
		SessionID:        "SESSION-1",
		SessionBindingID: "BINDING-1",
		Hostname:         "db.example.com",
		ProtocolSession:  protocolSession,
	})
	require.Empty(t, req.Session.ID)
	require.False(t, req.Postgres.ProtocolSession.IdentityValidated())
}

func TestEvaluatePostgresSessionRouteIDDoesNotExposeManagedCredentialRevision(t *testing.T) {
	t.Parallel()

	policy := config.Policy{
		From: "postgres://db.example.com",
		To:   mustParseWeightedURLs(t, "postgres://postgres.internal:5432"),
		RouteOptions: config.RouteOptions{
			Postgres: nullable.From(config.PostgresRouteSettings{
				AuthenticationMode: nullable.From(configpb.PostgresAuthenticationMode_POSTGRES_AUTHENTICATION_MODE_MANAGED),
				Username:           nullable.From("dbuser"),
				Database:           nullable.From("app"),
				Password:           nullable.From("managed-password-canary-one"),
			}),
		},
	}
	routeID, err := policy.RouteID()
	require.NoError(t, err)
	firstRevision, err := policy.PostgresRouteRevision()
	require.NoError(t, err)

	rotated := policy
	rotated.Postgres.Value.Password = nullable.From("managed-password-canary-two")
	rotatedRouteID, err := rotated.RouteID()
	require.NoError(t, err)
	rotatedRevision, err := rotated.PostgresRouteRevision()
	require.NoError(t, err)
	require.Equal(t, routeID, rotatedRouteID)
	require.NotEqual(t, firstRevision, rotatedRevision)
	require.NotEqual(t, routeID, firstRevision)
	require.NotEqual(t, routeID, rotatedRevision)

	for _, p := range []config.Policy{policy, rotated} {
		p.SubPolicies = []config.SubPolicy{{
			ID: "postgres-safe-route-id",
			Rego: []string{fmt.Sprintf(`
package pomerium.policy

allow {
	input.postgres.route_id == %q
	input.postgres.route_id != %q
	input.postgres.route_id != %q
}

`, routeID, firstRevision, rotatedRevision)},
		}}
		cfg := config.New(config.NewDefaultOptions())
		cfg.Options.Routes = []config.Policy{p}
		a, err := New(t.Context(), cfg)
		require.NoError(t, err)
		attachPostgresTestDatabroker(t, a)

		res, err := a.EvaluatePostgresSession(t.Context(), PostgresRequest{
			Hostname:         "db.example.com",
			SessionID:        "SESSION-1",
			SessionBindingID: "BINDING-1",
			ConfigGeneration: cfg,
		})
		require.NoError(t, err)
		require.True(t, res.Allow.Value)
		require.False(t, res.Deny.Value)
	}
}

func TestEvaluatePostgresSessionRejectsRouteRevisionMismatch(t *testing.T) {
	t.Parallel()
	policy := config.Policy{
		From: "postgres://db.example.com",
		To:   mustParseWeightedURLs(t, "postgres://postgres.internal:5432"),
		RouteOptions: config.RouteOptions{Postgres: nullable.From(config.PostgresRouteSettings{
			AuthenticationMode: nullable.From(configpb.PostgresAuthenticationMode_POSTGRES_AUTHENTICATION_MODE_MANAGED),
			Username:           nullable.From("dbuser"), Database: nullable.From("app"), Password: nullable.From("secret"),
		})},
	}
	cfg := config.New(config.NewDefaultOptions())
	cfg.Options.Routes = []config.Policy{policy}
	a, err := New(t.Context(), cfg)
	require.NoError(t, err)
	attachPostgresTestDatabroker(t, a)

	_, err = a.EvaluatePostgresSession(t.Context(), PostgresRequest{
		Hostname: "db.example.com", SessionID: "SESSION-1", SessionBindingID: "BINDING-1", RouteRevision: "stale-revision",
		ConfigGeneration: cfg,
	})
	require.ErrorContains(t, err, "route changed during authorization")
}

func TestEvaluatePostgresSessionFailsClosedWhileGenerationIsBuilding(t *testing.T) {
	cfgA := postgresGenerationTestConfig(true)
	cfgB := postgresGenerationTestConfig(false)
	db := postgresGenerationTestDatabroker(t)
	a, err := New(t.Context(), cfgA, WithDataBrokerServiceClient(db))
	require.NoError(t, err)

	buildEntered := make(chan struct{})
	releaseBuild := make(chan struct{})
	a.postgresConfigBuildHook = func(*config.Config) {
		close(buildEntered)
		<-releaseBuild
	}
	updated := make(chan struct{})
	go func() {
		a.OnConfigChange(t.Context(), cfgB)
		close(updated)
	}()
	<-buildEntered

	evaluated := make(chan error, 1)
	go func() {
		_, err := a.EvaluatePostgresSession(t.Context(), postgresGenerationTestRequest(cfgB))
		evaluated <- err
	}()
	select {
	case err := <-evaluated:
		require.ErrorContains(t, err, "configuration is not ready")
	case <-time.After(time.Second):
		t.Fatal("postgres authorization waited behind a generation build")
	}
	close(releaseBuild)
	<-updated

	res, err := a.EvaluatePostgresSession(t.Context(), postgresGenerationTestRequest(cfgB))
	require.NoError(t, err)
	require.False(t, res.Allow.Value, "allow policy from generation A survived deny generation B")
}

func TestEvaluatePostgresSessionExpiredContextDoesNotWaitForGenerationBuild(t *testing.T) {
	cfgA := postgresGenerationTestConfig(true)
	cfgB := postgresGenerationTestConfig(false)
	db := postgresGenerationTestDatabroker(t)
	a, err := New(t.Context(), cfgA, WithDataBrokerServiceClient(db))
	require.NoError(t, err)

	buildEntered := make(chan struct{})
	releaseBuild := make(chan struct{})
	a.postgresConfigBuildHook = func(*config.Config) {
		close(buildEntered)
		<-releaseBuild
	}
	updated := make(chan struct{})
	go func() {
		a.OnConfigChange(t.Context(), cfgB)
		close(updated)
	}()
	<-buildEntered

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	evaluated := make(chan error, 1)
	go func() {
		_, err := a.EvaluatePostgresSession(ctx, postgresGenerationTestRequest(cfgB))
		evaluated <- err
	}()
	select {
	case err := <-evaluated:
		require.ErrorContains(t, err, "configuration is not ready")
	case <-time.After(time.Second):
		t.Fatal("expired authorization context waited behind a generation build")
	}

	close(releaseBuild)
	<-updated
}

func TestEvaluatePostgresSessionRemainsClosedAfterFailedGenerationBuild(t *testing.T) {
	cfgA := postgresGenerationTestConfig(true)
	cfgB := postgresGenerationTestConfig(false)
	cfgB.Options.SigningKey = "not-a-valid-signing-key"
	db := postgresGenerationTestDatabroker(t)
	a, err := New(t.Context(), cfgA, WithDataBrokerServiceClient(db))
	require.NoError(t, err)

	a.OnConfigChange(t.Context(), cfgB)
	for _, cfg := range []*config.Config{cfgA, cfgB} {
		_, err := a.EvaluatePostgresSession(t.Context(), postgresGenerationTestRequest(cfg))
		require.ErrorContains(t, err, "configuration is not ready")
	}
}

func postgresGenerationTestConfig(allow bool) *config.Config {
	policyResult := "false"
	if allow {
		policyResult = "true"
	}
	opts := config.NewDefaultOptions()
	opts.Routes = []config.Policy{{
		From: "postgres://db.example.com",
		To:   mustParseWeightedURLsForPostgresGeneration("postgres://postgres.internal:5432"),
		RouteOptions: config.RouteOptions{Postgres: nullable.From(config.PostgresRouteSettings{
			AuthenticationMode: nullable.From(configpb.PostgresAuthenticationMode_POSTGRES_AUTHENTICATION_MODE_MANAGED),
			Username:           nullable.From("dbuser"), Database: nullable.From("app"), Password: nullable.From("secret"),
		})},
		SubPolicies: []config.SubPolicy{{
			ID:   "postgres-generation-policy",
			Rego: []string{"package pomerium.policy\nallow := " + policyResult},
		}},
	}}
	return config.New(opts)
}

func mustParseWeightedURLsForPostgresGeneration(raw string) config.WeightedURLs {
	u, err := config.ParseWeightedUrls(raw)
	if err != nil {
		panic(err)
	}
	return u
}

func postgresGenerationTestDatabroker(t *testing.T) databroker.DataBrokerServiceClient {
	t.Helper()
	db := testutil.NewTestDatabroker(t)
	putRecords(t, db,
		&session.Session{Id: "SESSION-1", UserId: "USER-1"},
		&user.User{Id: "USER-1", Email: "user@example.com"})
	return db
}

func postgresGenerationTestRequest(cfg *config.Config) PostgresRequest {
	return PostgresRequest{
		Hostname: "db.example.com", SessionID: "SESSION-1", SessionBindingID: "BINDING-1",
		ConfigGeneration: cfg,
	}
}

func attachPostgresTestDatabroker(t *testing.T, a *Authorize) {
	t.Helper()
	db := testutil.NewTestDatabroker(t)
	putRecords(t, db,
		&session.Session{
			Id:     "SESSION-1",
			UserId: "USER-1",
		},
		&user.User{
			Id:    "USER-1",
			Email: "user@example.com",
		})
	state := *a.state.Load()
	state.dataBrokerClient = db
	a.state.Store(&state)
	a.postgresMu.Lock()
	a.postgres.state = &state
	a.postgresMu.Unlock()
}
