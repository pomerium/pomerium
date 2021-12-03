package authenticate

import (
	"net/http"

	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/middleware"
	"github.com/pomerium/pomerium/internal/urlutil"
)

// requireValidSignatureOnRedirect validates the pomerium_signature if a redirect_uri or pomerium_signature
// is present on the query string.
func (a *Authenticate) requireValidSignatureOnRedirect(next httputil.HandlerFunc) http.Handler {
	return httputil.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		if r.FormValue(urlutil.QueryRedirectURI) != "" || r.FormValue(urlutil.QueryHmacSignature) != "" {
			err := middleware.ValidateRequestURL(a.getExternalRequest(r), a.state.Load().sharedKey)
			if err != nil {
				return httputil.NewError(http.StatusBadRequest, err)
			}
		}
		return next(w, r)
	})
}

// requireValidSignature validates the pomerium_signature.
func (a *Authenticate) requireValidSignature(next httputil.HandlerFunc) http.Handler {
	return httputil.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		err := middleware.ValidateRequestURL(a.getExternalRequest(r), a.state.Load().sharedKey)
		if err != nil {
			return err
		}
		return next(w, r)
	})
}

func (a *Authenticate) getExternalRequest(r *http.Request) *http.Request {
	options := a.options.Load()

	externalURL, err := options.GetAuthenticateURL()
	if err != nil {
		return r
	}

	internalURL, err := options.GetInternalAuthenticateURL()
	if err != nil {
		return r
	}

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
