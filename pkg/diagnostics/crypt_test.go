package diagnostics_test

import (
	"crypto/ecdh"
	"crypto/hpke"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/pomerium/pomerium/pkg/diagnostics"
)

func TestEncrypt(t *testing.T) {
	t.Parallel()
	k1, err := hpke.DHKEM(ecdh.X25519()).GenerateKey()
	assert.NoError(t, err)

	bs, err := diagnostics.Encrypt(0x17, k1.PublicKey(), []byte("test"))
	assert.NoError(t, err)
	bs, err = diagnostics.Decrypt(func(keyID byte, kemID, kdfID, aeadID uint16) (hpke.PrivateKey, error) {
		assert.Equal(t, byte(0x17), keyID)
		assert.Equal(t, uint16(0x0020), kemID)
		assert.Equal(t, uint16(0x0001), kdfID)
		assert.Equal(t, uint16(0x0002), aeadID)
		return k1, nil
	}, bs)
	assert.NoError(t, err)
	assert.Equal(t, string("test"), string(bs))
}
