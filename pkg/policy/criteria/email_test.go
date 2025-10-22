package criteria

import (
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/pomerium/datasource/pkg/directory"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpc/user"
)

func TestEmails(t *testing.T) {
	t.Parallel()

	t.Run("no session", func(t *testing.T) {
		res, err := evaluate(t, `
allow:
  and:
    - email:
        is: test@example.com
`, []*databroker.Record{}, Input{Session: InputSession{ID: "SESSION_ID"}})
		require.NoError(t, err)
		require.Equal(t, A{false, A{ReasonUserUnauthenticated}, M{}}, res["allow"])
		require.Equal(t, A{false, A{}}, res["deny"])
	})
	t.Run("by email", func(t *testing.T) {
		res, err := evaluate(t, `
allow:
  and:
    - email:
        is: test@example.com
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
		require.Equal(t, A{true, A{ReasonEmailOK}, M{}}, res["allow"])
		require.Equal(t, A{false, A{}}, res["deny"])
	})
	t.Run("by impersonate session id", func(t *testing.T) {
		res, err := evaluate(t, `
allow:
  and:
    - email:
        is: test2@example.com
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
				makeRecord(&user.User{
					Id:    "USER1",
					Email: "test1@example.com",
				}),
				makeRecord(&user.User{
					Id:    "USER2",
					Email: "test2@example.com",
				}),
			},
			Input{Session: InputSession{ID: "SESSION1"}})
		require.NoError(t, err)
		require.Equal(t, A{true, A{ReasonEmailOK}, M{}}, res["allow"])
		require.Equal(t, A{false, A{}}, res["deny"])
	})
	t.Run("by directory user", func(t *testing.T) {
		res, err := evaluate(t, `
allow:
  and:
    - email:
        is: test@example.com
`,
			[]*databroker.Record{
				makeRecord(&session.Session{
					Id:     "SESSION_ID",
					UserId: "USER_ID",
				}),
				makeStructRecord(directory.UserRecordType, "USER_ID", map[string]any{
					"email": "test@example.com",
				}),
			},
			Input{Session: InputSession{ID: "SESSION_ID"}})
		require.NoError(t, err)
		require.Equal(t, A{true, A{ReasonEmailOK}, M{}}, res["allow"])
		require.Equal(t, A{false, A{}}, res["deny"])
	})
}
