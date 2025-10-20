package criteria

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/pomerium/datasource/pkg/directory"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpc/user"
)

func TestDomains(t *testing.T) {
	t.Parallel()

	t.Run("no session", func(t *testing.T) {
		res, err := evaluate(t, `
allow:
  and:
    - domain:
        is: example.com
`, []*databroker.Record{}, Input{Session: InputSession{ID: "SESSION_ID"}})
		require.NoError(t, err)
		require.Equal(t, A{false, A{ReasonUserUnauthenticated}, M{}}, res["allow"])
		require.Equal(t, A{false, A{}}, res["deny"])
	})
	t.Run("by domain", func(t *testing.T) {
		res, err := evaluate(t, `
allow:
  and:
    - domain:
        is: example.com
`,
			[]*databroker.Record{
				makeRecord(&session.Session{
					Id:     "SESSION_ID",
					UserId: "USER_ID",
				}),
				makeRecord(&user.User{
					Id:    "USER_ID",
					Email: "test@example.com",
				}),
			},
			Input{Session: InputSession{ID: "SESSION_ID"}})
		require.NoError(t, err)
		require.Equal(t, A{true, A{ReasonDomainOK}, M{}}, res["allow"])
		require.Equal(t, A{false, A{}}, res["deny"])
	})
	t.Run("by impersonate email", func(t *testing.T) {
		res, err := evaluate(t, `
allow:
  and:
    - domain:
        is: example.com
`,
			[]*databroker.Record{
				makeRecord(&session.Session{
					Id:     "SESSION_ID",
					UserId: "USER_ID",
				}),
				makeRecord(&user.User{
					Id:    "USER_ID",
					Email: "test1@example.com",
				}),
			},
			Input{Session: InputSession{ID: "SESSION_ID"}})
		require.NoError(t, err)
		require.Equal(t, A{true, A{ReasonDomainOK}, M{}}, res["allow"])
		require.Equal(t, A{false, A{}}, res["deny"])
	})
	t.Run("by directory user", func(t *testing.T) {
		res, err := evaluate(t, `
allow:
  and:
    - domain:
        is: example.com
`,
			[]*databroker.Record{
				makeRecord(&session.Session{
					Id:     "SESSION_ID",
					UserId: "USER_ID",
				}),
				makeStructRecord(directory.UserRecordType, "USER_ID", map[string]any{
					"email": "user@example.com",
				}),
			},
			Input{Session: InputSession{ID: "SESSION_ID"}})
		require.NoError(t, err)
		require.Equal(t, A{true, A{ReasonDomainOK}, M{}}, res["allow"])
		require.Equal(t, A{false, A{}}, res["deny"])
	})
}
