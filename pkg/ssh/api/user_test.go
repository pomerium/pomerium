package api_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/pkg/ssh/api"
)

func TestUserRequest(t *testing.T) {
	t.Run("Empty value", func(t *testing.T) {
		var u api.UserRequest
		require.False(t, u.Valid())
		require.Panics(t, func() { _ = u.Username() })
		require.Panics(t, func() { _ = u.Hostname() })
	})

	t.Run("SetOrCheckEqual", func(t *testing.T) {
		var u api.UserRequest
		require.NoError(t, u.SetOrCheckEqual("user", "host"))
		require.Equal(t, "user", u.Username())
		require.Equal(t, "host", u.Hostname())

		assert.NoError(t, u.SetOrCheckEqual("user", "host"))
		assert.Equal(t, "user", u.Username())
		assert.Equal(t, "host", u.Hostname())

		assert.Error(t, u.SetOrCheckEqual("user", ""))
		assert.Equal(t, "user", u.Username())
		assert.Equal(t, "host", u.Hostname())

		assert.Error(t, u.SetOrCheckEqual("user", "host2"))
		assert.Equal(t, "user", u.Username())
		assert.Equal(t, "host", u.Hostname())

		assert.Error(t, u.SetOrCheckEqual("", "host"))
		assert.Equal(t, "user", u.Username())
		assert.Equal(t, "host", u.Hostname())

		assert.Error(t, u.SetOrCheckEqual("user2", "host"))
		assert.Equal(t, "user", u.Username())
		assert.Equal(t, "host", u.Hostname())

		assert.Error(t, u.SetOrCheckEqual("user2", "host2"))
		assert.Equal(t, "user", u.Username())
		assert.Equal(t, "host", u.Hostname())

		assert.Error(t, u.SetOrCheckEqual("", ""))
		assert.Equal(t, "user", u.Username())
		assert.Equal(t, "host", u.Hostname())
	})

	t.Run("PromoteFrom", func(t *testing.T) {
		t.Run("valid", func(t *testing.T) {
			var base api.UserRequest
			require.NoError(t, base.SetOrCheckEqual("user", ""))
			assert.Equal(t, "user", base.Username())
			assert.Equal(t, "", base.Hostname())

			var target api.UserRequest
			require.NoError(t, target.SetOrCheckEqual("user", "host"))

			assert.NoError(t, base.PromoteFrom(target))

			assert.Equal(t, "user", base.Username())
			assert.Equal(t, "host", base.Hostname())
		})
		t.Run("empty target hostname", func(t *testing.T) {
			var base api.UserRequest
			require.NoError(t, base.SetOrCheckEqual("user", ""))
			assert.Equal(t, "user", base.Username())
			assert.Equal(t, "", base.Hostname())

			var target api.UserRequest
			require.NoError(t, target.SetOrCheckEqual("user", ""))

			assert.ErrorContains(t, base.PromoteFrom(target), "hostname missing")
		})
		t.Run("inconsistent target username", func(t *testing.T) {
			var base api.UserRequest
			require.NoError(t, base.SetOrCheckEqual("user", ""))
			assert.Equal(t, "user", base.Username())
			assert.Equal(t, "", base.Hostname())

			var target api.UserRequest
			require.NoError(t, target.SetOrCheckEqual("user2", "host"))

			assert.ErrorContains(t, base.PromoteFrom(target), "username inconsistent")
		})
		t.Run("invalid states", func(t *testing.T) {
			{
				var base api.UserRequest
				require.NoError(t, base.SetOrCheckEqual("user", "host"))
				var target api.UserRequest
				require.NoError(t, target.SetOrCheckEqual("user", "host"))

				assert.Panics(t, func() {
					base.PromoteFrom(target)
				})
			}
			{
				var base api.UserRequest
				require.NoError(t, base.SetOrCheckEqual("user", "host"))
				var emptyTarget api.UserRequest

				assert.Panics(t, func() {
					base.PromoteFrom(emptyTarget)
				})
			}
			{
				var emptyBase api.UserRequest
				var target api.UserRequest
				require.NoError(t, target.SetOrCheckEqual("user", "host"))

				assert.Panics(t, func() {
					emptyBase.PromoteFrom(target)
				})
			}
			{
				var emptyBase api.UserRequest
				var emptyTarget api.UserRequest

				assert.Panics(t, func() {
					emptyBase.PromoteFrom(emptyTarget)
				})
			}
		})
	})
}

func TestNewUserRequest(t *testing.T) {
	t.Run("valid user/host", func(t *testing.T) {
		u, err := api.NewUserRequest("user", "host")
		assert.NoError(t, err)
		assert.True(t, u.Valid())
		assert.Equal(t, "user", u.Username())
		assert.Equal(t, "host", u.Hostname())
	})

	t.Run("invalid user", func(t *testing.T) {
		u, err := api.NewUserRequest("", "")
		assert.ErrorContains(t, err, "username missing")
		assert.False(t, u.Valid())
	})
}
