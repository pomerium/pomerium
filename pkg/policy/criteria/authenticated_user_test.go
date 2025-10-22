package criteria

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
)

func TestAuthenticatedUser(t *testing.T) {
	t.Parallel()

	t.Run("no session", func(t *testing.T) {
		res, err := evaluate(t, `
allow:
  and:
    - authenticated_user: 1
`, nil, Input{Session: InputSession{ID: "SESSION_ID"}})
		require.NoError(t, err)
		require.Equal(t, A{false, A{ReasonUserUnauthenticated}, M{}}, res["allow"])
		require.Equal(t, A{false, A{}}, res["deny"])
	})
	t.Run("by domain", func(t *testing.T) {
		res, err := evaluate(t, `
allow:
  and:
    - authenticated_user: 1
`,
			[]*databroker.Record{
				makeRecord(&session.Session{
					Id:     "SESSION_ID",
					UserId: "USER_ID",
				}),
			},
			Input{Session: InputSession{ID: "SESSION_ID"}})
		require.NoError(t, err)
		require.Equal(t, A{true, A{ReasonUserOK}, M{}}, res["allow"])
		require.Equal(t, A{false, A{}}, res["deny"])
	})
}
