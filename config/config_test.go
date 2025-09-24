package config_test

import (
	"crypto/ecdsa"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/pkg/cryptutil"
)

func TestGenerateCatchAllCertificate(t *testing.T) {
	expected := `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEILl9Nj1pmMzK/dHZ1yZcF1aPsCL0iqDsyHvIAyr4JNX+oAoGCCqGSM49
AwEHoUQDQgAEpDspy8qOG7ARSokzfO86qBnuMetrXUWhPoOU68aqr/KlsIW+KvX1
FiPqTUIoAXth7BiRbJ3gNjNEtdUV1Rtn3w==
-----END EC PRIVATE KEY-----
`
	cfg := &config.Config{Options: &config.Options{
		SharedKey: base64.StdEncoding.EncodeToString([]byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ123456")),
	}}
	cert, err := cfg.GenerateCatchAllCertificate()
	require.NoError(t, err)
	key, err := cryptutil.EncodePrivateKey(cert.PrivateKey.(*ecdsa.PrivateKey))
	require.NoError(t, err)
	assert.Equal(t, expected, string(key))

	cfg.Options.DeriveInternalDomainCert = proto.String("example.com")
	cert, err = cfg.GenerateCatchAllCertificate()
	require.NoError(t, err)
	key, err = cryptutil.EncodePrivateKey(cert.PrivateKey.(*ecdsa.PrivateKey))
	require.NoError(t, err)
	assert.Equal(t, expected, string(key))
}
