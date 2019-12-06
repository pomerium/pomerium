package urlutil // import "github.com/pomerium/pomerium/internal/urlutil"

import (
	"fmt"
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
		return nil, err
	}
	if err := ValidateURL(u); err != nil {
		return nil, err
	}
	return u, nil
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
