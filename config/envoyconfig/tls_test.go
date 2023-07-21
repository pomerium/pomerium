package envoyconfig

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/internal/testutil"
	"github.com/pomerium/pomerium/pkg/cryptutil"
)

func TestBuildSubjectAltNameMatcher(t *testing.T) {
	b := new(Builder)
	testutil.AssertProtoJSONEqual(t, `{
		"sanType": "DNS",
		"matcher": {
			"exact": "example.com"
		}
	}`, b.buildSubjectAltNameMatcher(&url.URL{Host: "example.com:1234"}, ""))
	testutil.AssertProtoJSONEqual(t, `{
		"sanType": "IP_ADDRESS",
		"matcher": {
			"exact": "10.0.0.1"
		}
	}`, b.buildSubjectAltNameMatcher(&url.URL{Host: "10.0.0.1:1234"}, ""))
	testutil.AssertProtoJSONEqual(t, `{
		"sanType": "IP_ADDRESS",
		"matcher": {
			"exact": "fd12:3456:789a:1::1"
		}
	}`, b.buildSubjectAltNameMatcher(&url.URL{Host: "[fd12:3456:789a:1::1]:1234"}, ""))
	testutil.AssertProtoJSONEqual(t, `{
		"sanType": "IP_ADDRESS",
		"matcher": {
			"exact": "fe80::1ff:fe23:4567:890a"
		}
	}`, b.buildSubjectAltNameMatcher(&url.URL{Host: "[fe80::1ff:fe23:4567:890a%eth2]:1234"}, ""))
	testutil.AssertProtoJSONEqual(t, `{
		"sanType": "DNS",
		"matcher": {
			"exact": "example.org"
		}
	}`, b.buildSubjectAltNameMatcher(&url.URL{Host: "example.com:1234"}, "example.org"))
	testutil.AssertProtoJSONEqual(t, `{
		"sanType": "DNS",
		"matcher": {
			"safeRegex": {
				"googleRe2": {},
				"regex": ".*\\.example\\.org"
			}
		}
	}`, b.buildSubjectAltNameMatcher(&url.URL{Host: "example.com:1234"}, "*.example.org"))
}

func TestBuildSubjectNameIndication(t *testing.T) {
	b := new(Builder)
	assert.Equal(t, "example.com", b.buildSubjectNameIndication(&url.URL{Host: "example.com:1234"}, ""))
	assert.Equal(t, "example.org", b.buildSubjectNameIndication(&url.URL{Host: "example.com:1234"}, "example.org"))
	assert.Equal(t, "example.example.org", b.buildSubjectNameIndication(&url.URL{Host: "example.com:1234"}, "*.example.org"))
}

func TestValidateCertificate(t *testing.T) {
	cert, err := cryptutil.GenerateCertificate(nil, "example.com", func(tpl *x509.Certificate) {
		// set the must staple flag on the cert
		tpl.ExtraExtensions = append(tpl.ExtraExtensions, pkix.Extension{
			Id: oidMustStaple,
		})
	})
	require.NoError(t, err)

	assert.Error(t, validateCertificate(cert), "should return an error for a must-staple TLS certificate that has no stapled OCSP response")
}
