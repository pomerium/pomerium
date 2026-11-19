package diagnostics_test

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/pkg/diagnostics"
)

func TestEncrypt(t *testing.T) {
	t.Parallel()
	k1, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	k1PrivateDER, err := x509.MarshalPKCS8PrivateKey(k1)
	require.NoError(t, err)
	k1PrivatePEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: k1PrivateDER})
	k1PublicDER, err := x509.MarshalPKIXPublicKey(k1.Public())
	require.NoError(t, err)
	k1PublicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: k1PublicDER})

	bs, err := diagnostics.Encrypt(0x17, string(k1PublicPEM), []byte("test"))
	assert.NoError(t, err)
	bs, err = diagnostics.Decrypt(map[byte]string{0x17: string(k1PrivatePEM)}, bs)
	assert.NoError(t, err)
	assert.Equal(t, string("test"), string(bs))
}
