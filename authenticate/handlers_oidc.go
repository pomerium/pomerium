package authenticate

import (
	"fmt"
	"net/http"

	"github.com/gorilla/mux"

	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/oidcprovider"
	"github.com/pomerium/pomerium/pkg/endpoints"
)

func (a *Authenticate) mountOIDCProviderHandlers(r *mux.Router) {
	r.Path(endpoints.PathOIDCToken).Methods(http.MethodPost).Handler(a.wrapOIDCProviderHandler((*oidcprovider.Handlers).HandleToken))
	r.Path(endpoints.PathOIDCUserInfo).Methods(http.MethodGet).Handler(a.wrapOIDCProviderHandler((*oidcprovider.Handlers).HandleUserInfo))
	r.Path(endpoints.PathOIDCJWKS).Methods(http.MethodGet).Handler(a.wrapOIDCProviderHandler((*oidcprovider.Handlers).HandleJWKS))
	r.Path(endpoints.PathWellKnownOpenIDConfiguration).Methods(http.MethodGet).Handler(a.wrapOIDCProviderHandler((*oidcprovider.Handlers).HandleOIDCConfiguration))

	// The OIDC Authorization Endpoint is user-facing and requires a valid Pomerium session.
	sr := r.NewRoute().Subrouter()
	sr.Use(a.VerifySession)
	sr.Path(endpoints.PathOIDCAuth).Methods(http.MethodGet).Handler(a.wrapOIDCProviderHandler((*oidcprovider.Handlers).HandleAuth))
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
