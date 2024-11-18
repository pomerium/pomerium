package config

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/pomerium/pomerium/internal/urlutil"
)

func TestFromURLMatchesRequestURL(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		pattern string
		input   string
		matches bool
	}{
		{"https://from.example.com", "https://from.example.com/some/path", true},
		{"https://from.example.com", "https://to.example.com/some/path", false},
		{"https://*.example.com", "https://from.example.com/some/path", true},
		{"https://*.example.com", "https://example.com/some/path", false},
		{"https://*.example.com", "https://from.example.com:8443/some/path", true},
	} {
		fromURL := urlutil.MustParseAndValidateURL(tc.pattern)
		requestURL := urlutil.MustParseAndValidateURL(tc.input)
		assert.Equal(t, tc.matches, FromURLMatchesRequestURL(fromURL, requestURL, true),
			"from-url: %s\nrequest-url: %s", tc.pattern, tc.input)
	}
}

func TestWildcardToRegex(t *testing.T) {
	t.Parallel()

	re, err := regexp.Compile(WildcardToRegex("*.internal.*.example.com", true))
	assert.NoError(t, err)
	assert.True(t, re.MatchString("a.internal.b.example.com"))
	assert.True(t, re.MatchString("a.internal.b.example.com:1234"))

	re, err = regexp.Compile(WildcardToRegex("*.internal.*.example.com:1234", true))
	assert.NoError(t, err)
	assert.False(t, re.MatchString("a.internal.b.example.com"))
	assert.True(t, re.MatchString("a.internal.b.example.com:1234"))
	assert.False(t, re.MatchString("a.internal.b.example.com:5678"))

	re, err = regexp.Compile(WildcardToRegex("*.internal.*.example.com", false))
	assert.NoError(t, err)
	assert.True(t, re.MatchString("a.internal.b.example.com"))
	assert.False(t, re.MatchString("a.internal.b.example.com:1234"))
}

func TestHasPort(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		in     string
		expect bool
	}{
		{"example.com:1234", true},
		{"example.com", false},
		{"[::]:1234", true},
		{"[::]", false},
	} {
		actual := HasPort(tc.in)
		assert.Equal(t, tc.expect, actual, "expected %s to be %v", tc.in, tc.expect)
	}
}
