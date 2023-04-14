package config

import (
	"net/url"
	"regexp"

	"github.com/pomerium/pomerium/internal/urlutil"
)

// FromDomains returns the domains for a "from" address.
func FromDomains(from string) []string {
	fromURL, err := urlutil.ParseAndValidateURL(from)
	if err != nil {
		return nil
	}
	return urlutil.GetDomainsForURL(fromURL)
}

// FromIsTCP returns true if the "from" address is a TCP route.
func FromIsTCP(from string) bool {
	fromURL, err := urlutil.ParseAndValidateURL(from)
	if err != nil {
		return false
	}
	return fromURL.Scheme == "tcp+http" || fromURL.Scheme == "tcp+https"
}

// FromMatchesHost returns true if the given "from" address matches the given host.
func FromMatchesHost(from string, host string) bool {
	for _, fromHost := range FromDomains(from) {
		if fromHost == host {
			return true
		}
	}
	return false
}

// FromMatchesURL returns true if the given "from" address matches the given url.
func FromMatchesURL(from string, requestURL url.URL) bool {
	return FromMatchesHost(from, requestURL.Host)
}

// FromRegexMatchesHost returns true if the given "from_regex" address matches the given host.
func FromRegexMatchesHost(fromRegex string, host string) bool {
	re, err := regexp.Compile(fromRegex)
	if err != nil {
		return false
	}
	return re.MatchString(host)
}

// FromRegexMatchesURL returns true if the given "from_regex" address matches the given url.
func FromRegexMatchesURL(fromRegex string, requestURL url.URL) bool {
	return FromRegexMatchesHost(fromRegex, requestURL.Host)
}
