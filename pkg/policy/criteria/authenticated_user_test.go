package criteria

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/pkg/grpc/session"
)

func TestAuthenticatedUser(t *testing.T) {
	t.Run("no session", func(t *testing.T) {
		res, err := evaluate(t, `
allow:
  and:
    - authenticated_user: 1
`, []dataBrokerRecord{}, Input{Session: InputSession{ID: "SESSION_ID"}})
		require.NoError(t, err)
		require.Equal(t, false, res["allow"])
		require.Equal(t, false, res["deny"])
	})
	t.Run("by domain", func(t *testing.T) {
		res, err := evaluate(t, `
allow:
  and:
    - authenticated_user: 1
`,
			[]dataBrokerRecord{
				&session.Session{
					Id:     "SESSION_ID",
					UserId: "USER_ID",
				},
			},
			Input{Session: InputSession{ID: "SESSION_ID"}})
		require.NoError(t, err)
		require.Equal(t, true, res["allow"])
		require.Equal(t, false, res["deny"])
	})
}
