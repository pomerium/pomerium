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
			err := middleware.ValidateRequestURL(r, a.options.Load().SharedKey)
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
		err := middleware.ValidateRequestURL(r, a.options.Load().SharedKey)
		if err != nil {
			return err
		}
		return next(w, r)
	})
}
