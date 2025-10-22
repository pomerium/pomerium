package criteria

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/pomerium/datasource/pkg/directory"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpc/user"
)

func TestSSHUsername(t *testing.T) {
	t.Parallel()

	t.Run("ok", func(t *testing.T) {
		res, err := evaluate(t, `
allow:
  and:
    - ssh_username:
        is: example-username
`, []*databroker.Record{}, Input{SSH: InputSSH{Username: "example-username"}})
		require.NoError(t, err)
		assert.Equal(t, A{true, A{ReasonSSHUsernameOK}, M{}}, res["allow"])
		assert.Equal(t, A{false, A{}}, res["deny"])
	})
	t.Run("shorthand", func(t *testing.T) {
		res, err := evaluate(t, `
allow:
  and:
    - ssh_username: example-username
`, []*databroker.Record{}, Input{SSH: InputSSH{Username: "example-username"}})
		require.NoError(t, err)
		assert.Equal(t, A{true, A{ReasonSSHUsernameOK}, M{}}, res["allow"])
		assert.Equal(t, A{false, A{}}, res["deny"])
	})
	t.Run("multiple ok", func(t *testing.T) {
		res, err := evaluate(t, `
allow:
  and:
    - ssh_username:
        in: [user1, user2, user3]
`, []*databroker.Record{}, Input{SSH: InputSSH{Username: "user2"}})
		require.NoError(t, err)
		assert.Equal(t, A{true, A{ReasonSSHUsernameOK}, M{}}, res["allow"])
		assert.Equal(t, A{false, A{}}, res["deny"])
	})
	t.Run("multiple unauthorized", func(t *testing.T) {
		res, err := evaluate(t, `
allow:
  and:
    - ssh_username:
        in: [user1, user2, user3]
`, []*databroker.Record{}, Input{SSH: InputSSH{Username: "user4"}})
		require.NoError(t, err)
		assert.Equal(t, A{false, A{ReasonSSHUsernameUnauthorized}, M{}}, res["allow"])
		assert.Equal(t, A{false, A{}}, res["deny"])
	})
}

func TestSSHUsernameFromEmail(t *testing.T) {
	t.Parallel()

	policy := `
allow:
  and:
    - ssh_username_matches_email:`
	t.Run("matches email from user", func(t *testing.T) {
		res, err := evaluate(t, policy,
			[]*databroker.Record{
				makeRecord(&session.Session{
					Id:     "SESSION_ID",
					UserId: "USER_ID",
				}),
				makeRecord(&user.User{
					Id:    "USER_ID",
					Email: "my-user@example.com",
				}),
			},
			Input{
				SSH:     InputSSH{Username: "my-user"},
				Session: InputSession{ID: "SESSION_ID"},
			})
		require.NoError(t, err)
		assert.Equal(t, A{true, A{ReasonSSHUsernameOK}, M{}}, res["allow"])
		assert.Equal(t, A{false, A{}}, res["deny"])
	})
	t.Run("matches email from directory", func(t *testing.T) {
		res, err := evaluate(t, policy,
			[]*databroker.Record{
				makeRecord(&session.Session{
					Id:     "SESSION_ID",
					UserId: "USER_ID",
				}),
				makeStructRecord(directory.UserRecordType, "USER_ID", map[string]any{
					"email": "my-user@example.com",
				}),
			},
			Input{
				SSH:     InputSSH{Username: "my-user"},
				Session: InputSession{ID: "SESSION_ID"},
			})
		require.NoError(t, err)
		assert.Equal(t, A{true, A{ReasonSSHUsernameOK}, M{}}, res["allow"])
		assert.Equal(t, A{false, A{}}, res["deny"])
	})
	t.Run("does not match", func(t *testing.T) {
		res, err := evaluate(t, policy,
			[]*databroker.Record{
				makeRecord(&session.Session{
					Id:     "SESSION_ID",
					UserId: "USER_ID",
				}),
				makeStructRecord(directory.UserRecordType, "USER_ID", map[string]any{
					"email": "my-user@example.com",
				}),
			},
			Input{
				SSH:     InputSSH{Username: "not-my-user"},
				Session: InputSession{ID: "SESSION_ID"},
			})

		require.NoError(t, err)
		assert.Equal(t, A{false, A{ReasonSSHUsernameUnauthorized}, M{}}, res["allow"])
		assert.Equal(t, A{false, A{}}, res["deny"])
	})
}

func TestSSHUsernameFromClaim(t *testing.T) {
	t.Parallel()

	t.Run("session claim ok", func(t *testing.T) {
		res, err := evaluate(t, `
allow:
  and:
    - ssh_username_matches_claim: username
`,
			[]*databroker.Record{
				makeRecord(&session.Session{
					Id:     "SESSION_ID",
					UserId: "USER_ID",
					Claims: map[string]*structpb.ListValue{
						"username": {Values: []*structpb.Value{
							structpb.NewStringValue("root"),
							structpb.NewStringValue("admin"),
						}},
					},
				}),
				makeRecord(&user.User{
					Id:    "USER_ID",
					Email: "test@example.com",
				}),
			},
			Input{
				SSH:     InputSSH{Username: "admin"},
				Session: InputSession{ID: "SESSION_ID"},
			},
		)
		require.NoError(t, err)
		assert.Equal(t, A{true, A{ReasonSSHUsernameOK}, M{}}, res["allow"])
		assert.Equal(t, A{false, A{}}, res["deny"])
	})
	t.Run("session claim unauthorized", func(t *testing.T) {
		res, err := evaluate(t, `
allow:
  and:
    - ssh_username_matches_claim: username
`,
			[]*databroker.Record{
				makeRecord(&session.Session{
					Id:     "SESSION_ID",
					UserId: "USER_ID",
					Claims: map[string]*structpb.ListValue{
						"username": {Values: []*structpb.Value{
							structpb.NewStringValue("root"),
							structpb.NewStringValue("admin"),
						}},
					},
				}),
				makeRecord(&user.User{
					Id:    "USER_ID",
					Email: "test@example.com",
				}),
			},
			Input{
				SSH:     InputSSH{Username: "other-username"},
				Session: InputSession{ID: "SESSION_ID"},
			},
		)
		require.NoError(t, err)
		assert.Equal(t, A{false, A{ReasonSSHUsernameUnauthorized}, M{}}, res["allow"])
		assert.Equal(t, A{false, A{}}, res["deny"])
	})
	t.Run("claim missing", func(t *testing.T) {
		res, err := evaluate(t, `
allow:
  and:
    - ssh_username_matches_claim: username
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
			Input{
				SSH:     InputSSH{Username: "admin"},
				Session: InputSession{ID: "SESSION_ID"},
			},
		)
		require.NoError(t, err)
		assert.Equal(t, A{false, A{ReasonSSHUsernameUnauthorized}, M{}}, res["allow"])
		assert.Equal(t, A{false, A{}}, res["deny"])
	})
}
