package criteria

import (
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpc/user"
)

func TestClaims(t *testing.T) {
	t.Run("no session", func(t *testing.T) {
		res, err := evaluate(t, `
allow:
  and:
    - claim/family_name: Smith
`, []dataBrokerRecord{}, Input{Session: InputSession{ID: "SESSION_ID"}})
		require.NoError(t, err)
		require.Equal(t, A{false, A{ReasonUserUnauthenticated}, M{}}, res["allow"])
		require.Equal(t, A{false, A{}}, res["deny"])
	})
	t.Run("no claim", func(t *testing.T) {
		res, err := evaluate(t, `
allow:
  and:
    - claim/family_name: Smith
`,
			[]dataBrokerRecord{
				&session.Session{
					Id:     "SESSION_ID",
					UserId: "USER_ID",
				},
			},
			Input{Session: InputSession{ID: "SESSION_ID"}})
		require.NoError(t, err)
		require.Equal(t, A{false, A{ReasonClaimUnauthorized}, M{}}, res["allow"])
		require.Equal(t, A{false, A{}}, res["deny"])
	})
	t.Run("by session claim", func(t *testing.T) {
		res, err := evaluate(t, `
allow:
  and:
    - claim/family_name: Smith
`,
			[]dataBrokerRecord{
				&session.Session{
					Id:     "SESSION_ID",
					UserId: "USER_ID",
					Claims: map[string]*structpb.ListValue{
						"family_name": {Values: []*structpb.Value{structpb.NewStringValue("Smith")}},
					},
				},
				&user.User{
					Id:    "USER_ID",
					Email: "test@example.com",
				},
			},
			Input{Session: InputSession{ID: "SESSION_ID"}})
		require.NoError(t, err)
		require.Equal(t, A{true, A{ReasonClaimOK}, M{}}, res["allow"])
		require.Equal(t, A{false, A{}}, res["deny"])
	})
	t.Run("by user claim", func(t *testing.T) {
		res, err := evaluate(t, `
allow:
  and:
    - claim/family_name: Smith
`,
			[]dataBrokerRecord{
				&session.Session{
					Id:     "SESSION_ID",
					UserId: "USER_ID",
				},
				&user.User{
					Id:    "USER_ID",
					Email: "test@example.com",
					Claims: map[string]*structpb.ListValue{
						"family_name": {Values: []*structpb.Value{structpb.NewStringValue("Smith")}},
					},
				},
			},
			Input{Session: InputSession{ID: "SESSION_ID"}})
		require.NoError(t, err)
		require.Equal(t, A{true, A{ReasonClaimOK}, M{}}, res["allow"])
		require.Equal(t, A{false, A{}}, res["deny"])
	})
	t.Run("special keys", func(t *testing.T) {
		res, err := evaluate(t, `
allow:
  and:
    - claim/example.com/key: value
`,
			[]dataBrokerRecord{
				&session.Session{
					Id:     "SESSION_ID",
					UserId: "USER_ID",
					Claims: map[string]*structpb.ListValue{
						"example.com/key": {Values: []*structpb.Value{structpb.NewStringValue("value")}},
					},
				},
				&user.User{
					Id:    "USER_ID",
					Email: "test@example.com",
				},
			},
			Input{Session: InputSession{ID: "SESSION_ID"}})
		require.NoError(t, err)
		require.Equal(t, A{true, A{ReasonClaimOK}, M{}}, res["allow"])
		require.Equal(t, A{false, A{}}, res["deny"])
	})
}
