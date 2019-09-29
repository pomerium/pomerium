package urlutil // import "github.com/pomerium/pomerium/internal/urlutil"

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/pomerium/pomerium/internal/cryptutil"
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
		return fmt.Errorf("%s url does contain a valid scheme. Did you mean https://%s?", u.String(), u.String())
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

var mockNow testTime

// testTime is safe to use concurrently.
type testTime struct {
	sync.Mutex
	mockNow int64
}

func (tt *testTime) setNow(n int64) {
	tt.Lock()
	tt.mockNow = n
	tt.Unlock()
}

func (tt *testTime) now() int64 {
	tt.Lock()
	defer tt.Unlock()
	return tt.mockNow
}

// timestamp returns the current timestamp, in seconds.
//
// For testing purposes, the function that generates the timestamp can be
// overridden. If not set, it will return time.Now().UTC().Unix().
func timestamp() int64 {
	if mockNow.now() == 0 {
		return time.Now().UTC().Unix()
	}
	return mockNow.now()
}

// SignedRedirectURL takes a destination URL and adds redirect_uri to it's
// query params, along with a timestamp and an keyed signature.
func SignedRedirectURL(key string, destination, u *url.URL) *url.URL {
	now := timestamp()
	rawURL := u.String()
	params, _ := url.ParseQuery(destination.RawQuery) // handled by incoming mux
	params.Set("redirect_uri", rawURL)
	params.Set("ts", fmt.Sprint(now))
	params.Set("sig", hmacURL(key, rawURL, now))
	destination.RawQuery = params.Encode()
	return destination
}

// hmacURL takes a redirect url string and timestamp and returns the base64
// encoded HMAC result.
func hmacURL(key, data string, timestamp int64) string {
	h := cryptutil.GenerateHMAC([]byte(fmt.Sprint(data, timestamp)), key)
	return base64.URLEncoding.EncodeToString(h)
}

// GetAbsoluteURL returns the current handler's absolute url.
// https://stackoverflow.com/a/23152483
func GetAbsoluteURL(r *http.Request) *url.URL {
	u := r.URL
	u.Scheme = "https"
	u.Host = r.Host
	return u
}
