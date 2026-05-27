package testenv

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"testing"

	envoy_data_accesslog_v3 "github.com/envoyproxy/go-control-plane/envoy/data/accesslog/v3"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/internal/controlplane"
)

func TestCertificateEventDict(t *testing.T) {
	cert := Certificate{
		Leaf: &x509.Certificate{
			Issuer: pkix.Name{
				Organization: []string{"Pomerium"},
				CommonName:   "issuer common name",
			},
			Subject: pkix.Name{
				CommonName: "subject common name",
			},
			DNSNames: []string{"www.example.com"},
		},
	}
	d, err := json.Marshal(cert.EventDict())
	require.NoError(t, err)

	// Verify that the EventDict() output matches the PopulateCertEventDict() output.
	envoyCert := &envoy_data_accesslog_v3.TLSProperties_CertificateProperties{
		SubjectAltName: []*envoy_data_accesslog_v3.TLSProperties_CertificateProperties_SubjectAltName{
			{
				San: &envoy_data_accesslog_v3.TLSProperties_CertificateProperties_SubjectAltName_Dns{
					Dns: "www.example.com",
				},
			},
		},
		Subject: "CN=subject common name",
		Issuer:  "CN=issuer common name,O=Pomerium",
	}
	dict := zerolog.Dict()
	controlplane.PopulateCertEventDict(envoyCert, dict)
	var b bytes.Buffer
	l := zerolog.New(&b)
	l.Info().Dict("cert", dict).Msg("log message")
	var logData map[string]any
	err = json.Unmarshal([]byte(b.String()), &logData)
	require.NoError(t, err)
	certData, err := json.Marshal(logData["cert"])
	require.NoError(t, err)

	assert.Equal(t, certData, d)
}
