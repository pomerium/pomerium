package handlers

import (
	"net/http"
	"net/url"

	"github.com/rs/cors"

	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/pkg/endpoints"
)

// WellKnownPomerium returns the /.well-known/pomerium handler.
func WellKnownPomerium(authenticateURL *url.URL) http.Handler {
	return cors.AllowAll().Handler(httputil.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		wellKnownURLs := struct {
			Issuer                string `json:"issuer"`
			OAuth2Callback        string `json:"authentication_callback_endpoint"` // RFC6749
			JSONWebKeySetURL      string `json:"jwks_uri"`                         // RFC7517
			FrontchannelLogoutURI string `json:"frontchannel_logout_uri"`          // https://openid.net/specs/openid-connect-frontchannel-1_0.html
		}{
			urlutil.GetAbsoluteURL(r).ResolveReference(&url.URL{Path: "/"}).String(),
			authenticateURL.ResolveReference(&url.URL{Path: endpoints.PathAuthenticateCallback}).String(),
			urlutil.GetAbsoluteURL(r).ResolveReference(&url.URL{Path: endpoints.PathJWKS}).String(),
			urlutil.GetAbsoluteURL(r).ResolveReference(&url.URL{Path: "/.pomerium/sign_out"}).String(),
		}
		httputil.RenderJSON(w, http.StatusOK, wellKnownURLs)
		return nil
	}))
}
