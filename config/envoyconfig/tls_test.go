package envoyconfig

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/pomerium/pomerium/internal/testutil"
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
