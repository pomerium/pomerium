// Package urlutil provides utility functions for working with go urls.
package urlutil

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	// DefaultLeeway defines the default leeway for matching NotBefore/Expiry claims.
	DefaultLeeway = 1.0 * time.Minute
)

// StripPort returns a host, without any port number.
//
// If Host is an IPv6 literal with a port number, Hostname returns the
// IPv6 literal without the square brackets. IPv6 literals may include
// a zone identifier.
func StripPort(hostport string) string {
	colon := strings.IndexByte(hostport, ':')
	if colon == -1 {
		return hostport
	}
	if i := strings.IndexByte(hostport, ']'); i != -1 {
		return strings.TrimPrefix(hostport[:i], "[")
	}
	return hostport[:colon]
}

// ParseAndValidateURL wraps standard library's default url.Parse because
// it's much more lenient about what type of urls it accepts than pomerium.
func ParseAndValidateURL(rawurl string) (*url.URL, error) {
	if rawurl == "" {
		return nil, fmt.Errorf("url cannot be empty")
	}
	u, err := url.Parse(rawurl)
	if err != nil {
		if strings.Contains(err.Error(), "first path segment in URL cannot contain colon") {
			err = fmt.Errorf("%w, have you specified protocol (ex: https)", err)
		}
		return nil, err
	}
	if err := ValidateURL(u); err != nil {
		return nil, err
	}
	return u, nil
}

// MustParseAndValidateURL parses the URL via ParseAndValidateURL but panics if there is an error.
// (useful for testing)
func MustParseAndValidateURL(rawURL string) url.URL {
	u, err := ParseAndValidateURL(rawURL)
	if err != nil {
		panic(err)
	}
	return *u
}

// ValidateURL wraps standard library's default url.Parse because
// it's much more lenient about what type of urls it accepts than pomerium.
func ValidateURL(u *url.URL) error {
	if u == nil {
		return fmt.Errorf("nil url")
	}
	if u.Scheme == "" {
		return fmt.Errorf("%s url does contain a valid scheme", u.String())
	}
	if u.Host == "" {
		return fmt.Errorf("%s url does contain a valid hostname", u.String())
	}
	return nil
}

// DeepCopy creates a deep copy of a *url.URL
func DeepCopy(u *url.URL) (*url.URL, error) {
	if u == nil {
		return nil, nil
	}
	return ParseAndValidateURL(u.String())
}

// GetAbsoluteURL returns the current handler's absolute url.
// https://stackoverflow.com/a/23152483
func GetAbsoluteURL(r *http.Request) *url.URL {
	u := r.URL
	u.Scheme = "https"
	u.Host = r.Host
	return u
}

// GetDomainsForURL returns the available domains for given url.
//
// For standard HTTP (80)/HTTPS (443) ports, it returns `example.com` and `example.com:<port>`.
// Otherwise, return the URL.Host value.
func GetDomainsForURL(u url.URL) []string {
	if IsTCP(&u) {
		return []string{u.Host}
	}

	var defaultPort string
	if u.Scheme == "http" {
		defaultPort = "80"
	} else {
		defaultPort = "443"
	}

	// for hosts like 'example.com:1234' we only return one route
	if _, p, err := net.SplitHostPort(u.Host); err == nil {
		if p != defaultPort {
			return []string{u.Host}
		}
	}

	// for everything else we return two routes: 'example.com' and 'example.com:443'
	return []string{u.Hostname(), net.JoinHostPort(u.Hostname(), defaultPort)}
}

// IsTCP returns whether or not the given URL is for TCP via HTTP Connect.
func IsTCP(u *url.URL) bool {
	return u.Scheme == "tcp+http" || u.Scheme == "tcp+https"
}

// Join joins elements of a URL with '/'.
func Join(elements ...string) string {
	var builder strings.Builder
	appendSlash := false
	for i, el := range elements {
		if appendSlash {
			builder.WriteByte('/')
		}
		if i > 0 && strings.HasPrefix(el, "/") {
			builder.WriteString(el[1:])
		} else {
			builder.WriteString(el)
		}
		appendSlash = !strings.HasSuffix(el, "/")
	}
	return builder.String()
}

// GetExternalRequest modifies a request so that it appears to be for an external URL instead of
// an internal URL.
func GetExternalRequest(internalURL, externalURL *url.URL, r *http.Request) *http.Request {
	// if we're not using a different internal URL there's nothing to do
	if externalURL.String() == internalURL.String() {
		return r
	}

	// replace the internal host with the external host
	er := r.Clone(r.Context())
	if er.URL.Host == internalURL.Host {
		er.URL.Host = externalURL.Host
	}
	if er.Host == internalURL.Host {
		er.Host = externalURL.Host
	}
	return er
}
