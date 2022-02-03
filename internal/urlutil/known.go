package urlutil

import (
	"net/http"
	"net/url"
)

// DefaultDeviceType is the default device type when none is specified.
const DefaultDeviceType = "any"

// RedirectURL returns the redirect URL from the query string or a cookie.
func RedirectURL(r *http.Request) (string, bool) {
	if v := r.FormValue(QueryRedirectURI); v != "" {
		return v, true
	}

	if c, err := r.Cookie(QueryRedirectURI); err == nil {
		return c.Value, true
	}

	return "", false
}

// SignOutURL returns the /.pomerium/sign_out URL.
func SignOutURL(r *http.Request, authenticateURL *url.URL, key []byte) string {
	u := authenticateURL.ResolveReference(&url.URL{
		Path: "/.pomerium/sign_out",
	})
	if redirectURI, ok := RedirectURL(r); ok {
		u.RawQuery = (&url.Values{
			QueryRedirectURI: {redirectURI},
		}).Encode()
	}
	return NewSignedURL(key, u).Sign().String()
}

// WebAuthnURL returns the /.pomerium/webauthn URL.
func WebAuthnURL(r *http.Request, authenticateURL *url.URL, key []byte, values url.Values) string {
	u := authenticateURL.ResolveReference(&url.URL{
		Path: "/.pomerium/webauthn",
		RawQuery: buildURLValues(values, url.Values{
			QueryDeviceType:      {DefaultDeviceType},
			QueryEnrollmentToken: nil,
			QueryRedirectURI: {authenticateURL.ResolveReference(&url.URL{
				Path: "/.pomerium/device-enrolled",
			}).String()},
		}).Encode(),
	})
	return NewSignedURL(key, u).Sign().String()
}

func buildURLValues(values, defaults url.Values) url.Values {
	result := make(url.Values)
	for k, vs := range defaults {
		if values.Has(k) {
			result[k] = values[k]
		} else if vs != nil {
			result[k] = vs
		}
	}
	return result
}
