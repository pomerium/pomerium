package criteria

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
)

func TestPostgresCriteria(t *testing.T) {
	t.Parallel()

	t.Run("username match", func(t *testing.T) {
		res, err := evaluate(t, `
allow:
  and:
    - postgres_username:
        is: alice
`, []*databroker.Record{}, Input{Postgres: InputPostgres{Username: "alice"}})
		require.NoError(t, err)
		require.Equal(t, A{true, A{ReasonPostgresUsernameOK}, M{}}, res["allow"])
		require.Equal(t, A{false, A{}}, res["deny"])
	})

	t.Run("database mismatch", func(t *testing.T) {
		res, err := evaluate(t, `
allow:
  and:
    - postgres_database:
        is: analytics
`, []*databroker.Record{}, Input{Postgres: InputPostgres{Database: "finance"}})
		require.NoError(t, err)
		require.Equal(t, A{false, A{ReasonPostgresDatabaseUnauthorized}, M{}}, res["allow"])
		require.Equal(t, A{false, A{}}, res["deny"])
	})

	t.Run("application name in list", func(t *testing.T) {
		res, err := evaluate(t, `
allow:
  and:
    - postgres_application_name:
        in: ["psql", "pgadmin"]
`, []*databroker.Record{}, Input{Postgres: InputPostgres{ApplicationName: "psql"}})
		require.NoError(t, err)
		require.Equal(t, A{true, A{ReasonPostgresApplicationNameOK}, M{}}, res["allow"])
		require.Equal(t, A{false, A{}}, res["deny"])
	})

	t.Run("statement class deny", func(t *testing.T) {
		res, err := evaluate(t, `
deny:
  and:
    - postgres_statement_class:
        in: ["DROP", "TRUNCATE"]
`, []*databroker.Record{}, Input{Postgres: InputPostgres{StatementClass: "DROP"}})
		require.NoError(t, err)
		require.Equal(t, A{true, A{ReasonPostgresStatementClassOK}, M{}}, res["deny"])
		require.Equal(t, A{false, A{}}, res["allow"])
	})
}
