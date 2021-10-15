package cryptutil

import (
	"strings"
	"testing"
	"time"

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

func TestSecureToken(t *testing.T) {
	key := []byte{1, 2, 3, 4, 5}
	expiry := time.Date(2021, 10, 14, 12, 27, 0, 0, time.UTC)
	token := Token(uuid.MustParse("38ad02ee-5db4-4246-9d4c-44e4a0077408"))
	secureToken := GenerateSecureToken(key, expiry, token)
	assert.Equal(t, "2Y2GNugUpcunes9epx9ehkdHwJvejtnBzNJ5iniiRYv3rMoE7LMN3tZmf7ZGNidJKMSvTtCYEqtE5", secureToken.String())
	assert.Equal(t, []byte{
		0x38, 0xad, 0x02, 0xee, 0x5d, 0xb4, 0x42, 0x46,
		0x9d, 0x4c, 0x44, 0xe4, 0xa0, 0x07, 0x74, 0x08,
		0x00, 0x00, 0x01, 0x7c, 0x7e, 0xc5, 0x1e, 0x20,
		0x39, 0xc5, 0xca, 0x5a, 0x77, 0xc4, 0xbc, 0x65,
		0x56, 0x22, 0x0b, 0x17, 0x7a, 0xae, 0x97, 0x4c,
		0xa9, 0x6a, 0x99, 0x69, 0x9e, 0xce, 0x20, 0xbd,
		0xd6, 0xba, 0xb9, 0x3c, 0x16, 0x30, 0x6d, 0x12,
	}, secureToken.Bytes())
	assert.Equal(t, [SecureTokenHMACLength]byte{
		0x39, 0xc5, 0xca, 0x5a, 0x77, 0xc4, 0xbc, 0x65,
		0x56, 0x22, 0x0b, 0x17, 0x7a, 0xae, 0x97, 0x4c,
		0xa9, 0x6a, 0x99, 0x69, 0x9e, 0xce, 0x20, 0xbd,
		0xd6, 0xba, 0xb9, 0x3c, 0x16, 0x30, 0x6d, 0x12,
	}, secureToken.HMAC())
	assert.Equal(t, Token{
		0x38, 0xad, 0x02, 0xee, 0x5d, 0xb4, 0x42, 0x46,
		0x9d, 0x4c, 0x44, 0xe4, 0xa0, 0x07, 0x74, 0x08,
	}, secureToken.Token())
	assert.Equal(t, expiry, secureToken.Expiry().UTC())

	t.Run("parse", func(t *testing.T) {
		parsed, ok := SecureTokenFromString("2Y2GNugUpcunes9epx9ehkdHwJvejtnBzNJ5iniiRYv3rMoE7LMN3tZmf7ZGNidJKMSvTtCYEqtE5")
		assert.True(t, ok)
		assert.Equal(t, secureToken, parsed)
	})

	t.Run("valid", func(t *testing.T) {
		err := secureToken.Verify(key, expiry.Add(-time.Second))
		assert.NoError(t, err)
	})
	t.Run("invalid", func(t *testing.T) {
		err := secureToken.Verify([]byte{6, 7, 8, 9, 0}, expiry.Add(time.Second))
		assert.Error(t, err)
	})
	t.Run("expired", func(t *testing.T) {
		err := secureToken.Verify(key, expiry.Add(time.Second))
		assert.Error(t, err)
	})
}
