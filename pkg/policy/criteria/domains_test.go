package criteria

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpc/user"
)

func TestDomains(t *testing.T) {
	t.Run("no session", func(t *testing.T) {
		res, err := evaluate(t, `
allow:
  and:
    - domain:
        is: example.com
`, []dataBrokerRecord{}, Input{Session: InputSession{ID: "SESSION_ID"}})
		require.NoError(t, err)
		require.Equal(t, false, res["allow"])
		require.Equal(t, false, res["deny"])
	})
	t.Run("by domain", func(t *testing.T) {
		res, err := evaluate(t, `
allow:
  and:
    - domain:
        is: example.com
`,
			[]dataBrokerRecord{
				&session.Session{
					Id:     "SESSION_ID",
					UserId: "USER_ID",
				},
				&user.User{
					Id:    "USER_ID",
					Email: "test@example.com",
				},
			},
			Input{Session: InputSession{ID: "SESSION_ID"}})
		require.NoError(t, err)
		require.Equal(t, true, res["allow"])
		require.Equal(t, false, res["deny"])
	})
	t.Run("by impersonate email", func(t *testing.T) {
		res, err := evaluate(t, `
allow:
  and:
    - domain:
        is: example.com
`,
			[]dataBrokerRecord{
				&session.Session{
					Id:     "SESSION_ID",
					UserId: "USER_ID",
				},
				&user.User{
					Id:    "USER_ID",
					Email: "test1@example.com",
				},
			},
			Input{Session: InputSession{ID: "SESSION_ID"}})
		require.NoError(t, err)
		require.Equal(t, true, res["allow"])
		require.Equal(t, false, res["deny"])
	})
}
