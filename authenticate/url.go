package authenticate

import (
	"net/http"
	"net/url"

	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/pkg/webauthnutil"
)

func (a *Authenticate) getRedirectURI(r *http.Request) (string, bool) {
	if v := r.FormValue(urlutil.QueryRedirectURI); v != "" {
		return v, true
	}

	if c, err := r.Cookie(urlutil.QueryRedirectURI); err == nil {
		return c.Value, true
	}

	return "", false
}

func (a *Authenticate) getSignOutURL(r *http.Request) (*url.URL, error) {
	uri, err := a.options.Load().GetAuthenticateURL()
	if err != nil {
		return nil, err
	}

	uri = uri.ResolveReference(&url.URL{
		Path: "/.pomerium/sign_out",
	})
	if redirectURI, ok := a.getRedirectURI(r); ok {
		uri.RawQuery = (&url.Values{
			urlutil.QueryRedirectURI: {redirectURI},
		}).Encode()
	}
	return urlutil.NewSignedURL(a.state.Load().sharedKey, uri).Sign(), nil
}

func (a *Authenticate) getWebAuthnURL(values url.Values) (*url.URL, error) {
	uri, err := a.options.Load().GetAuthenticateURL()
	if err != nil {
		return nil, err
	}

	uri = uri.ResolveReference(&url.URL{
		Path: "/.pomerium/webauthn",
		RawQuery: buildURLValues(values, url.Values{
			urlutil.QueryDeviceType:      {webauthnutil.DefaultDeviceType},
			urlutil.QueryEnrollmentToken: nil,
			urlutil.QueryRedirectURI: {uri.ResolveReference(&url.URL{
				Path: "/.pomerium/device-enrolled",
			}).String()},
		}).Encode(),
	})
	return urlutil.NewSignedURL(a.state.Load().sharedKey, uri).Sign(), nil
}
