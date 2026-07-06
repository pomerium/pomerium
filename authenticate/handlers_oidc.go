package authenticate

import (
	"fmt"
	"net/http"

	"github.com/gorilla/mux"

	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/oidcprovider"
)

func (a *Authenticate) mountOIDCProviderHandlers(r *mux.Router) {
	r.Path("/oidc/token").Methods(http.MethodPost).Handler(a.wrapOIDCProviderHandler((*oidcprovider.Handlers).HandleToken))
	r.Path("/oidc/userinfo").Methods(http.MethodGet).Handler(a.wrapOIDCProviderHandler((*oidcprovider.Handlers).HandleUserInfo))
	r.Path("/.well-known/jwks.json").Methods(http.MethodGet).Handler(a.wrapOIDCProviderHandler((*oidcprovider.Handlers).HandleJWKS))
	r.Path("/.well-known/openid-configuration").Methods(http.MethodGet).Handler(a.wrapOIDCProviderHandler((*oidcprovider.Handlers).HandleOIDCConfiguration))

	// XXX
	sr := r.NewRoute().Subrouter()
	sr.Use(a.VerifySession)
	sr.Path("/oidc/auth").Methods(http.MethodGet).Handler(a.wrapOIDCProviderHandler((*oidcprovider.Handlers).HandleAuth))
}

type oidcProviderHandlersFunc func(*oidcprovider.Handlers, http.ResponseWriter, *http.Request)

func (a *Authenticate) wrapOIDCProviderHandler(f oidcProviderHandlersFunc) httputil.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		handlers := a.state.Load().oidcProviderHandlers
		if handlers == nil {
			return httputil.NewError(http.StatusNotFound, fmt.Errorf("Not found"))
		}

		f(handlers, w, r)
		return nil
	}
}
