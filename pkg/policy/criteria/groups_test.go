package criteria

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/pkg/grpc/directory"
	"github.com/pomerium/pomerium/pkg/grpc/session"
)

func TestGroups(t *testing.T) {
	t.Run("no session", func(t *testing.T) {
		res, err := evaluate(t, `
allow:
  and:
    - groups: group1
    - groups: group2
`, []dataBrokerRecord{}, Input{Session: InputSession{ID: "SESSION_ID"}})
		require.NoError(t, err)
		require.Equal(t, false, res["allow"])
		require.Equal(t, false, res["deny"])
	})
	t.Run("by id", func(t *testing.T) {
		res, err := evaluate(t, `
allow:
  and:
    - groups: group1
`,
			[]dataBrokerRecord{
				&session.Session{
					Id:     "SESSION_ID",
					UserId: "USER_ID",
				},
				&directory.User{
					Id:       "USER_ID",
					GroupIds: []string{"group1"},
				},
			},
			Input{Session: InputSession{ID: "SESSION_ID"}})
		require.NoError(t, err)
		require.Equal(t, true, res["allow"])
		require.Equal(t, false, res["deny"])
	})
	t.Run("by email", func(t *testing.T) {
		res, err := evaluate(t, `
allow:
  and:
    - groups: "group1@example.com"
`,
			[]dataBrokerRecord{
				&session.Session{
					Id:     "SESSION_ID",
					UserId: "USER_ID",
				},
				&directory.User{
					Id:       "USER_ID",
					GroupIds: []string{"group1"},
				},
				&directory.Group{
					Id:    "group1",
					Email: "group1@example.com",
				},
			},
			Input{Session: InputSession{ID: "SESSION_ID"}})
		require.NoError(t, err)
		require.Equal(t, true, res["allow"])
		require.Equal(t, false, res["deny"])
	})
	t.Run("by name", func(t *testing.T) {
		res, err := evaluate(t, `
allow:
  and:
    - groups: "Group 1"
`,
			[]dataBrokerRecord{
				&session.Session{
					Id:     "SESSION_ID",
					UserId: "USER_ID",
				},
				&directory.User{
					Id:       "USER_ID",
					GroupIds: []string{"group1"},
				},
				&directory.Group{
					Id:   "group1",
					Name: "Group 1",
				},
			},
			Input{Session: InputSession{ID: "SESSION_ID"}})
		require.NoError(t, err)
		require.Equal(t, true, res["allow"])
		require.Equal(t, false, res["deny"])
	})
}
