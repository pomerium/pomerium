package proxy

import (
	"net/http"
	"net/url"

	"go.opentelemetry.io/otel"

	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/pkg/endpoints"
	"github.com/pomerium/pomerium/pkg/telemetry/trace"
)

// SignOut clears the local session and redirects the request to the sign out url.
// It's the responsibility of the authenticate service to revoke the remote session and clear
// the authenticate service's session handle.
func (p *Proxy) SignOut(w http.ResponseWriter, r *http.Request) error {
	state := p.state.Load()

	var redirectURL *url.URL
	signOutURL, err := p.currentConfig.Load().Options.GetSignOutRedirectURL()
	if err != nil {
		return httputil.NewError(http.StatusInternalServerError, err)
	}
	if signOutURL != nil {
		redirectURL = signOutURL
	}
	if uri, err := urlutil.ParseAndValidateURL(r.FormValue(urlutil.QueryRedirectURI)); err == nil && uri.String() != "" {
		redirectURL = uri
	}

	dashboardURL := state.authenticateDashboardURL.ResolveReference(&url.URL{
		Path: endpoints.PathPomeriumSignOut,
	})
	q := dashboardURL.Query()
	if redirectURL != nil {
		q.Set(urlutil.QueryRedirectURI, redirectURL.String())
	}
	otel.GetTextMapPropagator().Inject(r.Context(), trace.PomeriumURLQueryCarrier(q))
	dashboardURL.RawQuery = q.Encode()

	state.sessionStore.ClearSessionHandle(w)
	httputil.Redirect(w, r, urlutil.NewSignedURL(state.sharedKey, dashboardURL).String(), http.StatusFound)
	return nil
}
