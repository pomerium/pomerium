package proxy

import (
	"net/http"
	"net/url"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/pkg/endpoints"
)

// SignOut clears the local session and redirects the request to the sign out url.
// It's the responsibility of the authenticate service to revoke the remote session and clear
// the authenticate service's session handle.
func (p *Proxy) SignOut(w http.ResponseWriter, r *http.Request) error {
	state := p.state.Load()
	options := p.currentConfig.Load().Options

	var redirectURL *url.URL
	signOutURL, err := options.GetSignOutRedirectURL()
	if err != nil {
		return httputil.NewError(http.StatusInternalServerError, err)
	}
	if signOutURL != nil {
		redirectURL = signOutURL
	}
	if options.IsRuntimeFlagSet(config.RuntimeFlagAllowAnySignOutRedirectURI) {
		uri, err := urlutil.ParseAndValidateURL(r.FormValue(urlutil.QueryRedirectURI))
		if err == nil && uri.String() != "" {
			redirectURL = uri
		}
	}

	q := url.Values{}
	if redirectURL != nil {
		q.Set(urlutil.QueryRedirectURI, redirectURL.String())
	}

	state.sessionStore.ClearSessionHandle(w)
	return p.redirectToAuthenticateDashboard(w, r, authenticateDashboardRedirect{
		subPath: endpoints.SubPathSignOut,
		query:   q,
		sign:    true,
	})
}
