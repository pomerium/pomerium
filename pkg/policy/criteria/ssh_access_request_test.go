package criteria

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
)

func TestSSHAccessRequestApproved(t *testing.T) {
	t.Parallel()

	t.Run("not approved", func(t *testing.T) {
		res, err := evaluate(t, `
allow:
  and:
    - ssh_access_request_approved: {}
`, []*databroker.Record{}, Input{SSH: InputSSH{AccessRequestApproved: false}})
		require.NoError(t, err)
		assert.Equal(t, A{false, A{ReasonSSHAccessRequestRequired}, M{}}, res["allow"])
		assert.Equal(t, A{false, A{}}, res["deny"])
	})

	t.Run("approved", func(t *testing.T) {
		res, err := evaluate(t, `
allow:
  and:
    - ssh_access_request_approved: {}
`, []*databroker.Record{}, Input{SSH: InputSSH{AccessRequestApproved: true}})
		require.NoError(t, err)
		assert.Equal(t, A{true, A{ReasonSSHAccessRequestOK}, M{}}, res["allow"])
		assert.Equal(t, A{false, A{}}, res["deny"])
	})
}

func TestSSHAccessRequestNotApproved(t *testing.T) {
	t.Parallel()

	t.Run("denied", func(t *testing.T) {
		res, err := evaluate(t, `
deny:
  or:
    - ssh_access_request_not_approved: {}
`, []*databroker.Record{}, Input{SSH: InputSSH{AccessRequestApproved: false}})
		require.NoError(t, err)
		assert.Equal(t, A{false, A{}}, res["allow"])
		assert.Equal(t, A{true, A{ReasonSSHAccessRequestRequired}, M{}}, res["deny"])
	})

	t.Run("not denied", func(t *testing.T) {
		res, err := evaluate(t, `
deny:
  or:
    - ssh_access_request_not_approved: {}
`, []*databroker.Record{}, Input{SSH: InputSSH{AccessRequestApproved: true}})
		require.NoError(t, err)
		assert.Equal(t, A{false, A{}}, res["allow"])
		assert.Equal(t, A{false, A{ReasonSSHAccessRequestOK}, M{}}, res["deny"])
	})
}

func TestSSHAccessRequestIncorrectPolicies(t *testing.T) {
	t.Parallel()
	t.Run("ssh_access_request_not_approved in allow block", func(t *testing.T) {
		{ // this should be a no-op
			res, err := evaluate(t, `
allow:
  and:
    - ssh_access_request_not_approved: {}
`, []*databroker.Record{}, Input{SSH: InputSSH{AccessRequestApproved: false}})
			require.NoError(t, err)
			assert.Equal(t, A{true, A{ReasonSSHAccessRequestRequired}, M{}}, res["allow"])
			assert.Equal(t, A{false, A{}}, res["deny"])
		}

		{ // this shouldn't be possible normally
			res, err := evaluate(t, `
allow:
  and:
    - ssh_access_request_not_approved: {}
`, []*databroker.Record{}, Input{SSH: InputSSH{AccessRequestApproved: true}})
			require.NoError(t, err)
			assert.Equal(t, A{false, A{ReasonSSHAccessRequestOK}, M{}}, res["allow"])
			assert.Equal(t, A{false, A{}}, res["deny"])
		}
	})
	t.Run("ssh_access_request_approved in deny block", func(t *testing.T) {
		{ // this should be a no-op
			res, err := evaluate(t, `
deny:
  or:
    - ssh_access_request_approved: {}
`, []*databroker.Record{}, Input{SSH: InputSSH{AccessRequestApproved: false}})
			require.NoError(t, err)
			assert.Equal(t, A{false, A{}}, res["allow"])
			assert.Equal(t, A{false, A{ReasonSSHAccessRequestRequired}, M{}}, res["deny"])
		}

		{ // this shouldn't be possible normally
			res, err := evaluate(t, `
deny:
  or:
    - ssh_access_request_approved: {}
`, []*databroker.Record{}, Input{SSH: InputSSH{AccessRequestApproved: true}})
			require.NoError(t, err)
			assert.Equal(t, A{false, A{}}, res["allow"])
			assert.Equal(t, A{true, A{ReasonSSHAccessRequestOK}, M{}}, res["deny"])
		}
	})

	t.Run("contradiction", func(t *testing.T) {
		res, err := evaluate(t, `
allow:
  and:
    - ssh_access_request_approved: {}
    - ssh_access_request_not_approved: {}
`, []*databroker.Record{}, Input{SSH: InputSSH{AccessRequestApproved: false}})
		require.NoError(t, err)
		assert.Equal(t, A{false, A{ReasonSSHAccessRequestRequired}, M{}}, res["allow"])
		assert.Equal(t, A{false, A{}}, res["deny"])

		res, err = evaluate(t, `
allow:
  and:
    - ssh_access_request_approved: {}
    - ssh_access_request_not_approved: {}
`, []*databroker.Record{}, Input{SSH: InputSSH{AccessRequestApproved: true}})
		require.NoError(t, err)
		assert.Equal(t, A{false, A{ReasonSSHAccessRequestOK}, M{}}, res["allow"])
		assert.Equal(t, A{false, A{}}, res["deny"])

		res, err = evaluate(t, `
allow:
  and:
    - ssh_access_request_approved: {}
deny:
  or:
    - ssh_access_request_approved: {}
`, []*databroker.Record{}, Input{SSH: InputSSH{AccessRequestApproved: true}})
		require.NoError(t, err)
		assert.Equal(t, A{false, A{ReasonSSHAccessRequestOK}, M{}}, res["allow"])
		assert.Equal(t, A{false, A{}}, res["deny"])
	})

	t.Run("redundant criteria", func(t *testing.T) {
		res, err := evaluate(t, `
allow:
  and:
    - ssh_access_request_approved: {}
deny:
  or:
    - ssh_access_request_not_approved: {}
`, []*databroker.Record{}, Input{SSH: InputSSH{AccessRequestApproved: false}})
		require.NoError(t, err)
		assert.Equal(t, A{false, A{ReasonSSHAccessRequestRequired}, M{}}, res["allow"])
		assert.Equal(t, A{true, A{ReasonSSHAccessRequestRequired}, M{}}, res["deny"])

		res, err = evaluate(t, `
allow:
  and:
    - ssh_access_request_approved: {}
deny:
  or:
    - ssh_access_request_not_approved: {}
`, []*databroker.Record{}, Input{SSH: InputSSH{AccessRequestApproved: true}})
		require.NoError(t, err)
		assert.Equal(t, A{true, A{ReasonSSHAccessRequestOK}, M{}}, res["allow"])
		assert.Equal(t, A{false, A{ReasonSSHAccessRequestOK}, M{}}, res["deny"])
	})
}
