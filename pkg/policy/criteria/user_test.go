package criteria

import (
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/pomerium/pomerium/pkg/grpc/session"
)

func TestUser(t *testing.T) {
	t.Run("no session", func(t *testing.T) {
		res, err := evaluate(t, `
allow:
  and:
    - user:
        is: USER_ID
`, []dataBrokerRecord{}, Input{Session: InputSession{ID: "SESSION_ID"}})
		require.NoError(t, err)
		require.Equal(t, A{false, A{ReasonUserUnauthenticated}, M{}}, res["allow"])
		require.Equal(t, A{false, A{}}, res["deny"])
	})
	t.Run("by user id", func(t *testing.T) {
		res, err := evaluate(t, `
allow:
  and:
    - user:
        is: USER_ID
`,
			[]dataBrokerRecord{
				&session.Session{
					Id:     "SESSION_ID",
					UserId: "USER_ID",
				},
			},
			Input{Session: InputSession{ID: "SESSION_ID"}})
		require.NoError(t, err)
		require.Equal(t, A{true, A{ReasonUserOK}, M{}}, res["allow"])
		require.Equal(t, A{false, A{}}, res["deny"])
	})
	t.Run("by impersonate session id", func(t *testing.T) {
		res, err := evaluate(t, `
allow:
  and:
    - user:
        is: USER2
`,
			[]dataBrokerRecord{
				&session.Session{
					Id:                   "SESSION1",
					UserId:               "USER1",
					ImpersonateSessionId: proto.String("SESSION2"),
				},
				&session.Session{
					Id:     "SESSION2",
					UserId: "USER2",
				},
			},
			Input{Session: InputSession{ID: "SESSION1"}})
		require.NoError(t, err)
		require.Equal(t, A{true, A{ReasonUserOK}, M{}}, res["allow"])
		require.Equal(t, A{false, A{}}, res["deny"])
	})
}
