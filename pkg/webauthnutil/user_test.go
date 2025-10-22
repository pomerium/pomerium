package webauthnutil

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"github.com/pomerium/pomerium/pkg/grpc/user"
)

func TestGetUserEntity(t *testing.T) {
	t.Parallel()

	t.Run("name as email", func(t *testing.T) {
		ue := GetUserEntity(&user.User{
			Id:    "test",
			Email: "test@example.com",
		})
		assert.Equal(t, "test@example.com", ue.Name)
	})
	t.Run("name as id", func(t *testing.T) {
		ue := GetUserEntity(&user.User{
			Id: "test",
		})
		assert.Equal(t, "test", ue.Name)
	})
	t.Run("displayName as name", func(t *testing.T) {
		ue := GetUserEntity(&user.User{
			Id:   "test",
			Name: "Test User",
		})
		assert.Equal(t, "Test User", ue.DisplayName)
	})
	t.Run("displayName as email", func(t *testing.T) {
		ue := GetUserEntity(&user.User{
			Id:    "test",
			Email: "test@example.com",
		})
		assert.Equal(t, "test@example.com", ue.DisplayName)
	})
}

func TestGetUserEntityID(t *testing.T) {
	t.Parallel()

	userID := "test@example.com"
	rawUserEntityID := GetUserEntityID(userID)
	userEntityUUID, err := uuid.FromBytes(rawUserEntityID)
	assert.NoError(t, err, "should return a UUID")
	assert.Equal(t, "8c0ac353-406f-5c08-845d-b72779779a42", userEntityUUID.String())
}
