package hpke

import (
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEncryptURLValues(t *testing.T) {
	t.Parallel()

	k1, err := GeneratePrivateKey()
	require.NoError(t, err)
	k2, err := GeneratePrivateKey()
	require.NoError(t, err)

	t.Run("v1", func(t *testing.T) {
		t.Parallel()

		encrypted, err := EncryptURLValuesV1(k1, k2.PublicKey(), url.Values{
			"a": {"b", "c"},
			"x": {"y", "z"},
		})
		assert.NoError(t, err)
		assert.True(t, encrypted.Has(paramSenderPublicKey))
		assert.True(t, encrypted.Has(paramQuery))

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
	})
	t.Run("v2", func(t *testing.T) {
		t.Parallel()

		encrypted, err := EncryptURLValuesV2(k1, k2.PublicKey(), url.Values{
			"a": {"b", "c"},
			"x": {"y", "z"},
		})
		assert.NoError(t, err)
		assert.True(t, encrypted.Has(paramSenderPublicKeyV2))
		assert.True(t, encrypted.Has(paramQueryV2))

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
	})

	t.Run("compresses", func(t *testing.T) {
		t.Parallel()

		encrypted, err := EncryptURLValuesV2(k1, k2.PublicKey(), url.Values{
			"a": {strings.Repeat("b", 1024*128)},
		})
		assert.NoError(t, err)

		assert.Less(t, len(encrypted.Encode()), 1024)
	})
}

func BenchmarkZSTD(b *testing.B) {
	payload := url.Values{
		"a": {strings.Repeat("b", 128)},
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		bs := encodeQueryStringV2(payload)
		_, _ = decodeQueryStringV2(bs)
	}
}
