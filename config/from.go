package config

import (
	"net/url"

	"github.com/pomerium/pomerium/internal/urlutil"
)

// FromIsTCP returns true if the "from" address is a TCP route.
func FromIsTCP(from string) bool {
	fromURL, err := urlutil.ParseAndValidateURL(from)
	if err != nil {
		return false
	}
	return fromURL.Scheme == "tcp+http" || fromURL.Scheme == "tcp+https"
}

// FromMatchesURL returns true if the given "from" address matches the given url.
func FromMatchesURL(from string, requestURL url.URL) bool {
	return FromMatchesHost(from, requestURL.Host)
}

// FromMatchesHost returns true if the given "from" address matches the given host.
func FromMatchesHost(from string, host string) bool {
	fromURL, err := urlutil.ParseAndValidateURL(from)
	if err != nil {
		return false
	}

	// make sure one of the host domains matches the incoming url
	found := false
	for _, fromHost := range urlutil.GetDomainsForURL(fromURL) {
		found = found || fromHost == host
	}
	return found
}
