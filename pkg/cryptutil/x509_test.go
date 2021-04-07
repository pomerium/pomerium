package cryptutil

import (
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// generated using:
//   openssl genpkey -algorithm x25519 -out priv.pem
//   openssl pkey -in priv.pem -out pub.pem -pubout
var (
	rawPrivateX25519Key = []byte(`-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VuBCIEIKALoNgzCksH0v0Bc7Ghl8vGin4MAIKpmtZSmaMN0Vtb
-----END PRIVATE KEY-----
`)
	rawPublicX25519Key = []byte(`-----BEGIN PUBLIC KEY-----
MCowBQYDK2VuAyEAk63g8PY1JJTkrranWTxGSd/yA5kAgJlPk4/srMKg9mg=
-----END PUBLIC KEY-----
`)
)

func TestPKCS8PrivateKey(t *testing.T) {
	block, _ := pem.Decode(rawPrivateX25519Key)

	kek, err := ParsePKCS8PrivateKey(block.Bytes)
	assert.NoError(t, err)
	assert.IsType(t, &PrivateKeyEncryptionKey{}, kek)

	t.Run("marshal", func(t *testing.T) {
		der, err := MarshalPKCS8PrivateKey(kek)
		require.NoError(t, err)
		actual := pem.EncodeToMemory(&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: der,
		})
		assert.Equal(t, rawPrivateX25519Key, actual)
	})
}

func TestPKIXPublicKey(t *testing.T) {
	block, _ := pem.Decode(rawPublicX25519Key)

	kek, err := ParsePKIXPublicKey(block.Bytes)
	assert.NoError(t, err)
	assert.IsType(t, &PublicKeyEncryptionKey{}, kek)

	t.Run("marshal", func(t *testing.T) {
		der, err := MarshalPKIXPublicKey(kek)
		require.NoError(t, err)
		actual := pem.EncodeToMemory(&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: der,
		})
		assert.Equal(t, rawPublicX25519Key, actual)
	})
}
