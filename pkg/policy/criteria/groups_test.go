package criteria

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/pomerium/datasource/pkg/directory"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/policy/input"
)

func TestGroups(t *testing.T) {
	t.Run("no session", func(t *testing.T) {
		res, err := evaluate(t, `
allow:
  and:
    - groups:
        has: group1
    - groups:
        has: group2
`, []*databroker.Record{}, input.PolicyRequest{Session: input.RequestSession{ID: "session1"}})
		require.NoError(t, err)
		require.Equal(t, A{false, A{ReasonUserUnauthenticated}, M{}}, res["allow"])
		require.Equal(t, A{false, A{}}, res["deny"])
	})
	t.Run("by id", func(t *testing.T) {
		res, err := evaluate(t, `
allow:
  and:
    - groups:
        has: group1
`,
			[]*databroker.Record{
				makeRecord(&session.Session{
					Id:     "session1",
					UserId: "user1",
				}),
				makeStructRecord(directory.UserRecordType, "user1", map[string]any{
					"group_ids": []any{"group1", "group2"},
				}),
			},
			input.PolicyRequest{Session: input.RequestSession{ID: "session1"}})
		require.NoError(t, err)
		require.Equal(t, A{true, A{ReasonGroupsOK}, M{}}, res["allow"])
		require.Equal(t, A{false, A{}}, res["deny"])
	})
	t.Run("not allowed", func(t *testing.T) {
		res, err := evaluate(t, `
allow:
  and:
    - groups:
        has: group1
`,
			[]*databroker.Record{
				makeRecord(&session.Session{
					Id:     "session1",
					UserId: "user1",
				}),
				makeStructRecord(directory.UserRecordType, "user1", map[string]any{
					"group_ids": []any{"group2"},
				}),
			},
			input.PolicyRequest{Session: input.RequestSession{ID: "session1"}})
		require.NoError(t, err)
		require.Equal(t, A{false, A{ReasonGroupsUnauthorized}, M{}}, res["allow"])
		require.Equal(t, A{false, A{}}, res["deny"])
	})
}
