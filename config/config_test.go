package config_test

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/pomerium/pomerium/config"
)

func TestGenerateCatchAllCertificate(t *testing.T) {
	expected := `-----BEGIN CERTIFICATE-----
MIIBlzCCAT2gAwIBAgIRAPmKEV01Qa1gBWn9yUQPCFgwCgYIKoZIzj0EAwIwLTER
MA8GA1UEChMIUG9tZXJpdW0xGDAWBgNVBAMTD1BvbWVyaXVtIFBTSyBDQTAgFw0y
MjEyMDEwMDAwMDBaGA8yMDUwMTIwMTAwMDAwMFowEzERMA8GA1UEChMIUG9tZXJp
dW0wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASkOynLyo4bsBFKiTN87zqoGe4x
62tdRaE+g5Trxqqv8qWwhb4q9fUWI+pNQigBe2HsGJFsneA2M0S11RXVG2ffo1Yw
VDAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwEwHwYDVR0jBBgw
FoAU384OyoQVoqmKbzZbfHny25RhyqcwDAYDVR0RBAUwA4IBKjAKBggqhkjOPQQD
AgNIADBFAiEAitjxkg8yM/OWXGrzdUOA0gAh/c53/+7Gr45XEFCBMNQCIB3OzfDM
z/tcTCNUHYSh638283eNtxzfadbEhEjJ1Bpe
-----END CERTIFICATE-----
`
	cfg := &config.Config{Options: &config.Options{
		SharedKey: base64.StdEncoding.EncodeToString([]byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ123456")),
	}}
	cert, err := cfg.GenerateCatchAllCertificate()
	require.NoError(t, err)
	assertCertPEM(t, []string{expected}, cert)

	cfg.Options.DeriveInternalDomainCert = proto.String("example.com")
	cert, err = cfg.GenerateCatchAllCertificate()
	require.NoError(t, err)
	assertCertPEM(t, []string{expected}, cert)
}

func assertCertPEM(t *testing.T, expected []string, cert *tls.Certificate) {
	if assert.Len(t, cert.Certificate, len(expected)) {
		for i := range cert.Certificate {
			certPEM := pem.EncodeToMemory(&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: cert.Certificate[i],
			})
			assert.Equal(t, expected[i], string(certPEM))
		}
	}
}
