// Package urlutil provides utility functions for working with go urls.
package urlutil

import (
	"bytes"
	"fmt"
	"iter"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/certmagic"
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

type SharedURL struct {
	*url.URL
	hostname func() string
}

func (s *SharedURL) Hostname() string {
	return s.hostname()
}

func (s *SharedURL) Mutable() *url.URL {
	u := *s.URL
	if u.User != nil {
		user := *u.User
		u.User = &user
	}
	return &u
}

var urlCache sync.Map // map[string]*SharedURL

func ParseAndValidateSharedURL(rawurl string) (*SharedURL, error) {
	shared, ok := urlCache.Load(rawurl)
	if !ok {
		u, err := ParseAndValidateURL(rawurl)
		if err != nil {
			return nil, err
		}
		shared, _ = urlCache.LoadOrStore(rawurl, &SharedURL{
			URL:      u,
			hostname: sync.OnceValue(u.Hostname),
		})
	}
	return shared.(*SharedURL), nil
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
		return fmt.Errorf("%s url does not contain a valid scheme", u.String())
	}
	if u.Host == "" {
		return fmt.Errorf("%s url does not contain a valid hostname", u.String())
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

// GetServerNamesForURL returns the TLS server names for the given URL. The server name is the
// URL hostname.
func GetServerNamesForURL(u *url.URL) []string {
	if u == nil {
		return nil
	}

	return []string{u.Hostname()}
}

// GetDomainsForURL returns the available domains for given url.
//
// For standard HTTP (80)/HTTPS (443) ports, it returns `example.com` and `example.com:<port>`,
// if includeDefaultPort is set. Otherwise, return the URL.Host value.
func GetDomainsForURL(u *url.URL, includeDefaultPort bool) []string {
	if u == nil {
		return nil
	}

	// tcp+https://ssh.example.com:22
	// => ssh.example.com:22
	// tcp+https://proxy.example.com/ssh.example.com:22
	// => ssh.example.com:22
	if strings.HasPrefix(u.Scheme, "tcp+") {
		hosts := strings.Split(u.Path, "/")[1:]
		// if there are no domains in the path part of the URL, use the host
		if len(hosts) == 0 {
			return []string{u.Host}
		}
		// otherwise use the path parts of the URL as the hosts
		return hosts
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

	if !includeDefaultPort {
		return []string{u.Hostname()}
	}

	// for everything else we return two routes: 'example.com' and 'example.com:443'
	return []string{u.Hostname(), net.JoinHostPort(u.Hostname(), defaultPort)}
}

var (
	b80  = []byte("80")
	b443 = []byte("443")
)

func AllDomainsForURL(u *url.URL, includeDefaultPort bool) iter.Seq[string] {
	return func(yield func(string) bool) {
		if u == nil {
			return
		}

		// tcp+https://ssh.example.com:22
		// => ssh.example.com:22
		// tcp+https://proxy.example.com/ssh.example.com:22
		// => ssh.example.com:22
		if strings.HasPrefix(u.Scheme, "tcp+") {
			hosts := strings.Split(u.Path, "/")[1:]
			if len(hosts) == 0 {
				// if there are no domains in the path part of the URL, use the host
				yield(u.Host)
			} else {
				// otherwise use the path parts of the URL as the hosts
				for _, h := range hosts {
					if !yield(h) {
						break
					}
				}
			}
			return
		}

		var defaultPort []byte
		if u.Scheme == "http" {
			defaultPort = b80
		} else {
			defaultPort = b443
		}

		// for hosts like 'example.com:1234' we only return one route
		host, port := splitHostPort([]byte(u.Host))
		if len(port) > 0 {
			if !bytes.Equal(port, defaultPort) {
				yield(u.Host)
				return
			}
		}

		if !includeDefaultPort {
			yield(string(host))
			return
		}

		// for everything else we return two routes: 'example.com' and 'example.com:443'
		hostStr := string(host)
		if !yield(hostStr) {
			return
		}
		hostWithDefaultPort := strings.Builder{}
		hostWithDefaultPort.Write(host)
		hostWithDefaultPort.WriteByte(':')
		hostWithDefaultPort.Write(defaultPort)
		yield(hostWithDefaultPort.String())
	}
}

func splitHostPort(hostport []byte) ([]byte, []byte) {
	lastColonIdx := bytes.LastIndexByte(hostport, ':')
	if lastColonIdx < 0 {
		return hostport, nil
	}
	for i, l := lastColonIdx+1, len(hostport); i < l; i++ {
		if hostport[i] < '0' || hostport[i] > '9' {
			return hostport, nil
		}
	}
	if lastColonIdx > 1 && hostport[0] == '[' && hostport[lastColonIdx-1] == ']' {
		return hostport[1 : lastColonIdx-1], hostport[lastColonIdx+1:]
	}
	return hostport[:lastColonIdx], hostport[lastColonIdx+1:]
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

// MatchesServerName returnes true if the url's host matches the given server name.
func MatchesServerName(u url.URL, serverName string) bool {
	return certmagic.MatchWildcard(u.Hostname(), serverName)
}
