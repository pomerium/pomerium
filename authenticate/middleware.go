package authenticate

import (
	"net/http"

	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/urlutil"
)

// requireValidSignatureOnRedirect validates the pomerium_signature if a redirect_uri or pomerium_signature
// is present on the query string.
func (a *Authenticate) requireValidSignatureOnRedirect(next httputil.HandlerFunc) http.Handler {
	return httputil.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		if r.FormValue(urlutil.QueryRedirectURI) != "" || r.FormValue(urlutil.QueryHmacSignature) != "" {
			err := a.state.Load().flow.VerifyAuthenticateSignature(r)
			if err != nil {
				return httputil.NewError(http.StatusBadRequest, err)
			}
		}
		return next(w, r)
	})
}
