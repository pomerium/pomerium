package authenticate

import (
	"errors"
	"net/http"
	"net/url"

	"github.com/gorilla/mux"

	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/oidcbridge"
	"github.com/pomerium/pomerium/pkg/endpoints"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/identity/oidc"
)

func (a *Authenticate) mountOIDCBridgeHandlers(r *mux.Router) {
	r.Path(endpoints.PathOIDCToken).Methods(http.MethodPost).Handler(a.wrapOIDCBridgeHandler((*oidcbridge.Handlers).HandleToken))
	r.Path(endpoints.PathOIDCUserInfo).Methods(http.MethodGet, http.MethodPost).Handler(a.wrapOIDCBridgeHandler((*oidcbridge.Handlers).HandleUserInfo))
	r.Path(endpoints.PathOIDCJWKS).Methods(http.MethodGet).Handler(a.wrapOIDCBridgeHandler((*oidcbridge.Handlers).HandleJWKS))
	r.Path(endpoints.PathWellKnownOpenIDConfiguration).Methods(http.MethodGet).Handler(a.wrapOIDCBridgeHandler((*oidcbridge.Handlers).HandleOIDCConfiguration))

	// The OIDC Authorization Endpoint is user-facing and requires a valid
	// Pomerium session, which the handler checks itself: whether a missing or
	// stale session sends the user to sign in depends on the request.
	r.Path(endpoints.PathOIDCAuth).Methods(http.MethodGet, http.MethodPost).Handler(a.wrapOIDCBridgeHandler(
		func(h *oidcbridge.Handlers, w http.ResponseWriter, r *http.Request) {
			h.HandleAuth(w, r, oidcBridgeSessions{a})
		}))
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

// oidcBridgeSessions implements [oidcbridge.SessionAuthenticator].
type oidcBridgeSessions struct {
	a *Authenticate
}

func (s oidcBridgeSessions) VerifiedSessionHandle(r *http.Request) (*session.Handle, error) {
	return s.a.verifiedSessionHandle(r)
}

var errOIDCBridgeSignInRequired = errors.New("oidc bridge: sign-in required")

func (s oidcBridgeSessions) Reauthenticate(w http.ResponseWriter, r *http.Request, idpParams url.Values) error {
	if len(idpParams) > 0 {
		r = r.WithContext(oidc.WithSignInParams(r.Context(), idpParams))
	}
	return s.a.reauthenticateOrFail(w, r, errOIDCBridgeSignInRequired)
}
