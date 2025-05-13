package criteria

import (
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/policy/input"
)

func TestUser(t *testing.T) {
	t.Run("no session", func(t *testing.T) {
		res, err := evaluate(t, `
allow:
  and:
    - user:
        is: USER_ID
`, []*databroker.Record{}, input.PolicyRequest{Session: input.RequestSession{ID: "SESSION_ID"}})
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
			[]*databroker.Record{
				makeRecord(&session.Session{
					Id:     "SESSION_ID",
					UserId: "USER_ID",
				}),
			},
			input.PolicyRequest{Session: input.RequestSession{ID: "SESSION_ID"}})
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
			[]*databroker.Record{
				makeRecord(&session.Session{
					Id:                   "SESSION1",
					UserId:               "USER1",
					ImpersonateSessionId: proto.String("SESSION2"),
				}),
				makeRecord(&session.Session{
					Id:     "SESSION2",
					UserId: "USER2",
				}),
			},
			input.PolicyRequest{Session: input.RequestSession{ID: "SESSION1"}})
		require.NoError(t, err)
		require.Equal(t, A{true, A{ReasonUserOK}, M{}}, res["allow"])
		require.Equal(t, A{false, A{}}, res["deny"])
	})
}
