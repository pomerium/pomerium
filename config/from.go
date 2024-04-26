package config

import (
	"net/url"
	"regexp"
	"strings"

	"github.com/pomerium/pomerium/internal/urlutil"
)

// FromURLMatchesRequestURL returns true if the from URL matches the request URL.
func FromURLMatchesRequestURL(fromURL, requestURL *url.URL, stripPort bool) bool {
	for _, domain := range urlutil.GetDomainsForURL(fromURL, true) {
		if domain == requestURL.Host {
			return true
		}

		if !strings.Contains(domain, "*") {
			continue
		}

		reStr := WildcardToRegex(domain, stripPort)
		re := regexp.MustCompile(reStr)
		if re.MatchString(requestURL.Host) {
			return true
		}
	}
	return false
}

// WildcardToRegex converts a wildcard string to a regular expression.
func WildcardToRegex(wildcard string, stripPort bool) string {
	var b strings.Builder
	b.WriteByte('^')
	for {
		idx := strings.IndexByte(wildcard, '*')
		if idx < 0 {
			break
		}
		b.WriteString(regexp.QuoteMeta(wildcard[:idx]))
		b.WriteString("(.*)")
		wildcard = wildcard[idx+1:]
	}
	b.WriteString(regexp.QuoteMeta(wildcard))
	if stripPort && !HasPort(wildcard) {
		b.WriteString("(:(.+))?")
	}
	b.WriteByte('$')
	return b.String()
}

// HasPort returns true if the host has a port specifier.
func HasPort(host string) bool {
	idx := strings.LastIndex(host, ":")
	if idx < 0 {
		return false
	}
	if strings.HasPrefix(host, "[") {
		bracketIdx := strings.LastIndex(host, "]")
		return idx > bracketIdx
	}
	return true
}
