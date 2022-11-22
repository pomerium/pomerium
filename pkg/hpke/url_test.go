package hpke

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEncryptURLValues(t *testing.T) {
	k1, err := GeneratePrivateKey()
	require.NoError(t, err)
	k2, err := GeneratePrivateKey()
	require.NoError(t, err)

	encrypted, err := EncryptURLValues(k1, k2.PublicKey(), url.Values{
		"a": {"b", "c"},
		"x": {"y", "z"},
	})
	assert.NoError(t, err)
	assert.True(t, encrypted.Has(ParamSenderPublicKey))
	assert.True(t, encrypted.Has(ParamQuery))

	assert.True(t, IsEncryptedURL(encrypted))

	encrypted.Set("extra", "value")
	encrypted.Set("a", "notb")
	senderPublicKey, decrypted, err := DecryptURLValues(k2, encrypted)
	assert.NoError(t, err)
	assert.Equal(t, url.Values{
		"a":     {"b", "c"},
		"x":     {"y", "z"},
		"extra": {"value"},
	}, decrypted)
	assert.Equal(t, k1.PublicKey().String(), senderPublicKey.String())
}
