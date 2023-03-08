package urlutil

import (
	"net/http"
	"net/url"
)

// HPKEPublicKeyPath is the well-known path to the HPKE public key
const HPKEPublicKeyPath = "/.well-known/pomerium/hpke-public-key"

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

// Device paths
const (
	WebAuthnURLPath    = "/.pomerium/webauthn"
	DeviceEnrolledPath = "/.pomerium/device-enrolled"
)

// WebAuthnURL returns the /.pomerium/webauthn URL.
func WebAuthnURL(r *http.Request, authenticateURL *url.URL, key []byte, values url.Values) string {
	u := authenticateURL.ResolveReference(&url.URL{
		Path: WebAuthnURLPath,
		RawQuery: buildURLValues(values, url.Values{
			QueryDeviceType:      {DefaultDeviceType},
			QueryEnrollmentToken: nil,
			QueryRedirectURI: {authenticateURL.ResolveReference(&url.URL{
				Path: DeviceEnrolledPath,
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
