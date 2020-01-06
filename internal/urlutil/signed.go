package urlutil // import "github.com/pomerium/pomerium/internal/urlutil"

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"strconv"
	"time"

	"github.com/pomerium/pomerium/internal/cryptutil"
)

// SignedURL is a shared-key HMAC wrapped URL.
type SignedURL struct {
	uri    url.URL
	key    string
	signed bool

	// mockable time for testing
	timeNow func() time.Time
}

// NewSignedURL creates a new copy of a URL that can be signed with a shared key.
// It is the user's responsibility to make sure the key is 256 bits and
// the url is not nil.
func NewSignedURL(key string, uri *url.URL) *SignedURL {
	return &SignedURL{uri: *uri, key: key, timeNow: time.Now}
}

// Sign creates a shared-key HMAC signed URL. Scheme is ignored for signing.
func (su *SignedURL) Sign() *url.URL {
	urlScheme := su.uri.Scheme
	su.uri.Scheme = ""
	now := su.timeNow()
	issued := newNumericDate(now)
	expiry := newNumericDate(now.Add(5 * time.Minute))
	params := su.uri.Query()
	params.Set(QueryHmacIssued, fmt.Sprint(issued))
	params.Set(QueryHmacExpiry, fmt.Sprint(expiry))
	su.uri.RawQuery = params.Encode()
	params.Set(QueryHmacSignature, hmacURL(su.key, su.uri.String(), issued, expiry))
	su.uri.RawQuery = params.Encode()
	su.signed = true
	su.uri.Scheme = urlScheme
	return &su.uri
}

// String implements the stringer interface and returns a signed URL string.
func (su *SignedURL) String() string {
	if !su.signed {
		su.Sign()
		su.signed = true
	}
	return su.uri.String()
}

// Validate checks to see if a signed URL is valid.
func (su *SignedURL) Validate() error {
	su.uri.Scheme = ""
	now := su.timeNow()
	params := su.uri.Query()
	sig, err := base64.URLEncoding.DecodeString(params.Get(QueryHmacSignature))
	if err != nil {
		return fmt.Errorf("internal/urlutil: malformed signature %w", err)
	}
	params.Del(QueryHmacSignature)
	su.uri.RawQuery = params.Encode()
	issued, err := newNumericDateFromString(params.Get(QueryHmacIssued))
	if err != nil {
		return err
	}

	expiry, err := newNumericDateFromString(params.Get(QueryHmacExpiry))
	if err != nil {
		return err
	}

	if expiry != nil && now.Add(-DefaultLeeway).After(expiry.Time()) {
		return ErrExpired
	}

	if issued != nil && now.Add(DefaultLeeway).Before(issued.Time()) {
		return ErrIssuedInTheFuture
	}

	validHMAC := cryptutil.CheckHMAC(
		[]byte(fmt.Sprint(su.uri.String(), issued, expiry)),
		sig,
		su.key)
	if !validHMAC {
		return fmt.Errorf("internal/urlutil: hmac failed")
	}
	return nil
}

// hmacURL takes a redirect url string and timestamp and returns the base64
// encoded HMAC result.
func hmacURL(key string, data ...interface{}) string {
	h := cryptutil.GenerateHMAC([]byte(fmt.Sprint(data...)), key)
	return base64.URLEncoding.EncodeToString(h)
}

// numericDate used because we don't need the precision of a typical time.Time.
type numericDate int64

func newNumericDate(t time.Time) *numericDate {
	if t.IsZero() {
		return nil
	}
	out := numericDate(t.Unix())
	return &out
}

func newNumericDateFromString(s string) (*numericDate, error) {
	i, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return nil, ErrNumericDateMalformed
	}
	out := numericDate(i)
	return &out, nil
}

func (n *numericDate) Time() time.Time {
	if n == nil {
		return time.Time{}
	}
	return time.Unix(int64(*n), 0)
}

func (n *numericDate) String() string {
	return strconv.FormatInt(int64(*n), 10)
}
