package oidcbridge

import (
	"crypto/sha256"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/pkg/nullable"
)

func setupClientLookup(t *testing.T, c *ClientLookup, routes []config.Policy) {
	// We need to call Validate() to ensure that path regex matching works
	// correctly, as it sets some internal state. However this also requires
	// that each route has a valid 'To' setting. Setting this here lets the
	// test cases feature only the relevant details for each test case.
	for i := range routes {
		routes[i].To = config.WeightedURLs{{URL: url.URL{Scheme: "http", Host: "localhost:1234"}}}
	}
	o := config.NewDefaultOptions()
	o.Routes = routes
	require.NoError(t, o.Validate())

	c.buildForConfig(o)
}

func TestClientLookup(t *testing.T) {
	var c ClientLookup
	setup := func(routes []config.Policy) {
		setupClientLookup(t, &c, routes)
	}

	testLookupOK := func(clientID, clientSecret string) func(t *testing.T) {
		return func(t *testing.T) {
			t.Helper()
			info, err := c.Lookup(clientID, clientID)
			assert.NoError(t, err)
			assert.Equal(t, clientID, info.ID)
			hash := sha256.Sum256([]byte(clientSecret))
			assert.Equal(t, hash[:], info.SecretHash)
		}
	}
	testLookupNotFound := func(clientID string) func(t *testing.T) {
		return func(t *testing.T) {
			t.Helper()
			info, err := c.Lookup(clientID, clientID)
			assert.Nil(t, info)
			assert.ErrorContains(t, err, "unknown client_id")
		}
	}

	assert.True(t, c.Empty())

	// Lookup should return client info only for a route with the OIDCBridge
	// option set.
	setup([]config.Policy{
		{
			From: "https://enabled.example.com",
			OidcBridge: nullable.From(config.OIDCBridge{
				ClientSecret: nullable.From("secret"),
			}),
		},
		{
			From: "https://not-enabled.example.com",
		},
	})
	assert.False(t, c.Empty())

	t.Run("enabled", testLookupOK("https://enabled.example.com", "secret"))
	t.Run("not enabled", testLookupNotFound("https://not-enabled.example.com"))

	// Route path matching options must be satisfied.
	setup([]config.Policy{
		{
			From: "https://example.com",
			Path: "/foo",
			OidcBridge: nullable.From(config.OIDCBridge{
				ClientSecret: nullable.From("foo"),
			}),
		},
		{
			From:   "https://example.com",
			Prefix: "/bar",
			OidcBridge: nullable.From(config.OIDCBridge{
				ClientSecret: nullable.From("bar"),
			}),
		},
		{
			From:  "https://example.com",
			Regex: ".*/baz",
			OidcBridge: nullable.From(config.OIDCBridge{
				ClientSecret: nullable.From("baz"),
			}),
		},
	})
	assert.False(t, c.Empty())

	t.Run("path match", testLookupOK("https://example.com/foo", "foo"))
	t.Run("path mismatch", testLookupNotFound("https://example.com/foo/something"))
	t.Run("prefix match", testLookupOK("https://example.com/bar/something", "bar"))
	t.Run("regex match", testLookupOK("https://example.com/foo/bar/baz", "baz"))

	// Lookup should not fall through to the wildcard routes if a non-wildcard
	// route host matches.
	setup([]config.Policy{
		{
			From:   "https://non-wildcard.example.com",
			Prefix: "/path-prefix",
			OidcBridge: nullable.From(config.OIDCBridge{
				ClientSecret: nullable.From("non-wildcard"),
			}),
		},
		{
			From: "https://*-wildcard.example.com",
			OidcBridge: nullable.From(config.OIDCBridge{
				ClientSecret: nullable.From("wildcard"),
			}),
		},
	})
	assert.False(t, c.Empty())

	t.Run("non-wildcard match", testLookupOK("https://non-wildcard.example.com/path-prefix/foo-bar", "non-wildcard"))
	t.Run("no wildcard fallthrough", testLookupNotFound("https://non-wildcard.example.com/non-matching-path"))
	t.Run("valid wildcard", testLookupOK("https://other-wildcard.example.com/some-path", "wildcard"))
}

func TestClientLookup_ValidatesRedirectURI(t *testing.T) {
	var c ClientLookup
	setupClientLookup(t, &c, []config.Policy{
		{
			From:       "https://regular.example.com",
			OidcBridge: nullable.From(config.OIDCBridge{}),
		},
		{
			From:       "https://path-options.example.com",
			Prefix:     "/path-prefix",
			OidcBridge: nullable.From(config.OIDCBridge{}),
		},
		{
			From:       "https://path-options.example.com",
			Path:       "/exact-path",
			OidcBridge: nullable.From(config.OIDCBridge{}),
		},
		{
			From:       "https://path-options.example.com",
			Regex:      "/foo|/bar",
			OidcBridge: nullable.From(config.OIDCBridge{}),
		},
		{
			From:       "https://*-wildcard.example.com",
			OidcBridge: nullable.From(config.OIDCBridge{}),
		},
	})

	assertValid := func(t *testing.T, clientID, redirectURI string) {
		_, err := c.Lookup(clientID, redirectURI)
		assert.NoError(t, err)
	}
	assertNotValid := func(t *testing.T, clientID, redirectURI string) {
		_, err := c.Lookup(clientID, redirectURI)
		assert.Error(t, err)
	}

	// The host must always match.
	assertNotValid(t, "https://regular.example.com", "https://other.example.com")
	assertNotValid(t, "https://regular.example.com:1234", "https://regular.example.com")
	assertNotValid(t, "https://regular.example.com", "https://regular.example.com:1234")
	assertNotValid(t, "https://foo-wildcard.example.com", "https://bar-wildcard.example.com")

	// For routes without path options (whether wildcard or non-wildcard), the
	// redirect_uri can be any child of the client_id.
	assertValid(t, "https://regular.example.com", "https://regular.example.com")
	assertValid(t, "https://regular.example.com", "https://regular.example.com/oidc/callback")
	assertValid(t, "https://regular.example.com/app-1", "https://regular.example.com/app-1")
	assertValid(t, "https://regular.example.com/app-1", "https://regular.example.com/app-1/callback")
	assertNotValid(t, "https://regular.example.com/app-1", "https://regular.example.com/app-2")
	assertNotValid(t, "https://regular.example.com/app-1", "https://regular.example.com/app-123")
	assertNotValid(t, "https://regular.example.com/app/something", "https://regular.example.com/app")
	assertValid(t, "https://foo-wildcard.example.com", "https://foo-wildcard.example.com/callback")
	assertValid(t, "https://bar-wildcard.example.com", "https://bar-wildcard.example.com/callback")

	// The client_id can end in a '/' character so as long as the redirect_uri
	// has a matching '/' (just be consistent).
	assertValid(t, "https://regular.example.com/", "https://regular.example.com/")
	assertValid(t, "https://regular.example.com/", "https://regular.example.com/oidc/callback")
	assertValid(t, "https://regular.example.com/app-1/", "https://regular.example.com/app-1/")
	assertValid(t, "https://regular.example.com/app-1/", "https://regular.example.com/app-1/callback")
	assertNotValid(t, "https://regular.example.com/", "https://regular.example.com")
	assertNotValid(t, "https://regular.example.com/app-1/", "https://regular.example.com/app-1")

	// Any route path matching options must be met by both URLs.
	assertValid(t, "https://path-options.example.com/exact-path", "https://path-options.example.com/exact-path")
	assertNotValid(t, "https://path-options.example.com/exact-path", "https://path-options.example.com/exact")
	assertNotValid(t, "https://path-options.example.com/exact-path", "https://path-options.example.com/exact-path/callback")
	assertValid(t, "https://path-options.example.com/path-prefix", "https://path-options.example.com/path-prefix")
	assertValid(t, "https://path-options.example.com/path-prefix", "https://path-options.example.com/path-prefix/callback")
	assertValid(t, "https://path-options.example.com/foo", "https://path-options.example.com/foo")
	assertNotValid(t, "https://path-options.example.com/foo", "https://path-options.example.com/foo/callback")
	assertNotValid(t, "https://path-options.example.com/foo", "https://path-options.example.com/bar")
	assertValid(t, "https://path-options.example.com/bar", "https://path-options.example.com/bar")
	assertNotValid(t, "https://path-options.example.com/bar", "https://path-options.example.com/foo")

	// Both the client_id and redirect_uri must be valid URLs.
	_, err := c.Lookup("foobar", "foobar")
	assert.ErrorContains(t, err, "invalid client_id")
	_, err = c.Lookup("https://example.com", "https://example.com/?param")
	assert.ErrorContains(t, err, "invalid redirect_uri")
}

func TestParseURL(t *testing.T) {
	okCases := []string{
		"https://foo.example.com",
		"https://foo.example.com/",
		"https://foo.example.com/bar",
		"https://foo.example.com/bar/",
		"https://foo.example.com:1234/bar/",
	}
	for _, url := range okCases {
		t.Run("ok", func(t *testing.T) {
			_, err := parseURL(url)
			assert.NoError(t, err)
		})
	}

	errorCases := []struct {
		url      string
		errorMsg string
	}{
		{"http://example.com", `URL scheme must be "https"`},
		{"https://example.com?bar", "URL must not contain query parameters"},
		{"https://example.com#baz", "URL must not contain a fragment"},
		{"https://user@example.com", "URL must not contain a username or password"},
		{"https://user:pass@example.com", "URL must not contain a username or password"},
		{"https://example\x00.com", "invalid control character"},
		{"https://example.com/foo?", "invalid URL path"},
		{"https://example.com//", "invalid URL path"},
		{"https://example.com/../relative/path", "invalid URL path"},
		{"https://example.com/extra/./path", "invalid URL path"},
		{"https://example.com/double//slash", "invalid URL path"},
		{"https://*-example.com", "invalid URL hostname"},
		{"https://underscore_in_host.com", "invalid URL hostname"},
		{"https://[2001:db8::1]:1234/", "invalid URL hostname"},
	}
	for _, c := range errorCases {
		t.Run("error", func(t *testing.T) {
			_, err := parseURL(c.url)
			assert.ErrorContains(t, err, c.errorMsg)
		})
	}
}
