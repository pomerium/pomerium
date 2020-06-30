package cryptutil

import (
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestToken_String(t *testing.T) {
	v, _ := uuid.Parse("4aa29ffe-d802-4990-9be6-6adb4cd7af59")
	tok := Token(v)
	assert.Equal(t, "ADYZhBgVmT5Phd31hszpHN", tok.String())
}

func TestToken_UUID(t *testing.T) {
	v, _ := uuid.Parse("4aa29ffe-d802-4990-9be6-6adb4cd7af59")
	tok := Token(v)
	assert.Equal(t, v, tok.UUID())
}

func TestTokenFromString(t *testing.T) {
	v, _ := uuid.Parse("4aa29ffe-d802-4990-9be6-6adb4cd7af59")
	tok1 := Token(v)
	tok2, ok := TokenFromString("ADYZhBgVmT5Phd31hszpHN")
	assert.True(t, ok)
	assert.Equal(t, tok1, tok2)

	t.Run("invalid", func(t *testing.T) {
		_, ok := TokenFromString("<<<NOT VALID>>>")
		assert.False(t, ok)
	})
}

func TestNewRandomToken(t *testing.T) {
	uuid.SetRand(strings.NewReader("1111111111111111111111111111111"))
	defer uuid.SetRand(nil)

	tok := NewRandomToken()
	assert.Equal(t, "75KUW8tPVJWUnXBaApZfPE", tok.String())
}

func TestSecretToken_String(t *testing.T) {
	v1, _ := uuid.Parse("fb297629-e61f-4f1d-bb7e-ece3ed702098")
	v2, _ := uuid.Parse("047fb3ad-b1c7-463b-b16c-e41836811cc2")
	actual := SecretToken{
		ID:     Token(v1),
		Secret: Token(v2),
	}.String()
	assert.Equal(t, "HuS14FdpunfDzMWTwxzuXN5vqHf4H8bAqbwbo98onbjo", actual)

	t.Run("invalid", func(t *testing.T) {
		_, ok := SecretTokenFromString("<<<NOT VALID>>>")
		assert.False(t, ok)
	})
}

func TestSecretTokenFromString(t *testing.T) {
	tok, ok := SecretTokenFromString("HuS14FdpunfDzMWTwxzuXN5vqHf4H8bAqbwbo98onbjo")
	assert.True(t, ok)
	assert.Equal(t, "fb297629-e61f-4f1d-bb7e-ece3ed702098", tok.ID.UUID().String())
	assert.Equal(t, "047fb3ad-b1c7-463b-b16c-e41836811cc2", tok.Secret.UUID().String())
}
