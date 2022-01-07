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

func TestBuildSubjectAlternativeNameMatcher(t *testing.T) {
	b := new(Builder)
	testutil.AssertProtoJSONEqual(t, `
		{ "exact": "example.com" }
	`, b.buildSubjectAlternativeNameMatcher(&url.URL{Host: "example.com:1234"}, ""))
	testutil.AssertProtoJSONEqual(t, `
		{ "exact": "example.org" }
	`, b.buildSubjectAlternativeNameMatcher(&url.URL{Host: "example.com:1234"}, "example.org"))
	testutil.AssertProtoJSONEqual(t, `
		{ "safeRegex": {
			"googleRe2": {},
			"regex": ".*\\.example\\.org"
		} }
	`, b.buildSubjectAlternativeNameMatcher(&url.URL{Host: "example.com:1234"}, "*.example.org"))
}

func TestBuildSubjectNameIndication(t *testing.T) {
	b := new(Builder)
	assert.Equal(t, "example.com", b.buildSubjectNameIndication(&url.URL{Host: "example.com:1234"}, ""))
	assert.Equal(t, "example.org", b.buildSubjectNameIndication(&url.URL{Host: "example.com:1234"}, "example.org"))
	assert.Equal(t, "example.example.org", b.buildSubjectNameIndication(&url.URL{Host: "example.com:1234"}, "*.example.org"))
}

func TestValidateCertificatge(t *testing.T) {
	cert, err := cryptutil.GenerateSelfSignedCertificate("example.com", func(tpl *x509.Certificate) {
		// set the must staple flag on the cert
		tpl.ExtraExtensions = append(tpl.ExtraExtensions, pkix.Extension{
			Id: oidMustStaple,
		})
	})
	require.NoError(t, err)

	assert.Error(t, validateCertificate(cert), "should return an error for a must-staple TLS certificate that has no stapled OCSP response")
}
