package authenticate

import (
	"errors"
	"net/http"

	"github.com/gorilla/mux"

	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/oidcbridge"
	"github.com/pomerium/pomerium/pkg/endpoints"
)

func (a *Authenticate) mountOIDCBridgeHandlers(r *mux.Router) {
	r.Path(endpoints.PathOIDCToken).Methods(http.MethodPost).Handler(a.wrapOIDCBridgeHandler((*oidcbridge.Handlers).HandleToken))
	r.Path(endpoints.PathOIDCUserInfo).Methods(http.MethodGet).Handler(a.wrapOIDCBridgeHandler((*oidcbridge.Handlers).HandleUserInfo))
	r.Path(endpoints.PathOIDCJWKS).Methods(http.MethodGet).Handler(a.wrapOIDCBridgeHandler((*oidcbridge.Handlers).HandleJWKS))
	r.Path(endpoints.PathWellKnownOpenIDConfiguration).Methods(http.MethodGet).Handler(a.wrapOIDCBridgeHandler((*oidcbridge.Handlers).HandleOIDCConfiguration))

	// The OIDC Authorization Endpoint is user-facing and requires a valid Pomerium session.
	sr := r.NewRoute().Subrouter()
	sr.Use(a.VerifySession)
	sr.Path(endpoints.PathOIDCAuth).Methods(http.MethodGet).Handler(a.wrapOIDCBridgeHandler((*oidcbridge.Handlers).HandleAuth))
}

type oidcBridgeHandlersFunc func(*oidcbridge.Handlers, http.ResponseWriter, *http.Request)

var errOIDCBridgeNotEnabled = errors.New("OIDC bridge is not enabled")

func (a *Authenticate) wrapOIDCBridgeHandler(f oidcBridgeHandlersFunc) httputil.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		handlers := a.state.Load().oidcBridgeHandlers
		if handlers == nil {
			return httputil.NewError(http.StatusNotFound, errOIDCBridgeNotEnabled)
		}

		f(handlers, w, r)
		return nil
	}
}
