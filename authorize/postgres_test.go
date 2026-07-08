package authorize

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/authorize/evaluator"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/pkg/databrokerutil/testutil"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpc/user"
	"github.com/pomerium/pomerium/pkg/policy/criteria"
)

func TestEvaluatePostgresSession(t *testing.T) {
	t.Parallel()

	cfg := config.New(config.NewDefaultOptions())
	cfg.Options.Routes = []config.Policy{
		{
			From: "postgres://db.example.com",
			To: config.WeightedURLs{{
				URL: url.URL{Scheme: "postgres", Host: "postgres.internal:5432", User: url.UserPassword("dbuser", "secret")},
			}},
			Policy: parsePPL(t, `
- allow:
    and:
      - postgres_database:
          is: app
      - postgres_username:
          is: alice
`),
		},
	}

	a, err := New(t.Context(), cfg)
	require.NoError(t, err)
	attachPostgresTestDatabroker(t, a)

	res, err := a.EvaluatePostgresSession(t.Context(), PostgresRequest{
		Hostname:         "db.example.com",
		Database:         "app",
		Username:         "alice",
		SessionID:        "SESSION-1",
		SessionBindingID: "BINDING-1",
	})
	require.NoError(t, err)
	assert.Equal(t, evaluator.NewRuleResult(true, criteria.ReasonPostgresDatabaseOK, criteria.ReasonPostgresUsernameOK), res.Allow)
	assert.Equal(t, evaluator.NewRuleResult(false), res.Deny)
}

func TestEvaluatePostgresQuery(t *testing.T) {
	t.Parallel()

	cfg := config.New(config.NewDefaultOptions())
	cfg.Options.Routes = []config.Policy{
		{
			From: "postgres://db.example.com",
			To: config.WeightedURLs{{
				URL: url.URL{Scheme: "postgres", Host: "postgres.internal:5432", User: url.UserPassword("dbuser", "secret")},
			}},
			Policy: parsePPL(t, `
- deny:
    and:
      - postgres_statement_class:
          in: ["DROP", "TRUNCATE"]
`),
		},
	}

	a, err := New(t.Context(), cfg)
	require.NoError(t, err)
	attachPostgresTestDatabroker(t, a)

	res, err := a.EvaluatePostgresQuery(t.Context(), PostgresRequest{
		Hostname:         "db.example.com",
		Database:         "app",
		Username:         "alice",
		StatementClass:   "DROP",
		QueryProtocol:    "simple",
		SessionID:        "SESSION-1",
		SessionBindingID: "BINDING-1",
	})
	require.NoError(t, err)
	assert.Equal(t, evaluator.NewRuleResult(false), res.Allow)
	assert.Equal(t, evaluator.NewRuleResult(true, criteria.ReasonPostgresStatementClassOK), res.Deny)
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
}
