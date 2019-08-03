package urlutil // import "github.com/pomerium/pomerium/internal/urlutil"

import (
	"fmt"
	"net/url"
	"strings"
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
		return nil, err
	}
	if u.Scheme == "" {
		return nil, fmt.Errorf("%s url does contain a valid scheme. Did you mean https://%s?", rawurl, rawurl)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("%s url does contain a valid hostname", rawurl)
	}
	return u, nil
}

func DeepCopy(u *url.URL) (*url.URL, error) {
	if u == nil {
		return nil, nil
	}
	return ParseAndValidateURL(u.String())
}
