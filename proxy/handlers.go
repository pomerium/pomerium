package proxy

import (
	"errors"
	"io"
	"net/http"
	"net/url"

	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/gorilla/mux"

	"github.com/pomerium/pomerium/internal/handlers"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/middleware"
	"github.com/pomerium/pomerium/internal/urlutil"
)

// registerDashboardHandlers returns the proxy service's ServeMux
func (p *Proxy) registerDashboardHandlers(r *mux.Router) *mux.Router {
	h := httputil.DashboardSubrouter(r)
	h.Use(middleware.SetHeaders(httputil.HeadersContentSecurityPolicy))

	// special pomerium endpoints for users to view their session
	h.Path("/").Handler(httputil.HandlerFunc(p.userInfo)).Methods(http.MethodGet)
	h.Path("/device-enrolled").Handler(httputil.HandlerFunc(p.deviceEnrolled))
	h.Path("/jwt").Handler(httputil.HandlerFunc(p.jwtAssertion)).Methods(http.MethodGet)
	h.Path("/sign_out").Handler(httputil.HandlerFunc(p.SignOut)).Methods(http.MethodGet, http.MethodPost)
	h.Path("/webauthn").Handler(p.webauthn)

	// called following authenticate auth flow to grab a new or existing session
	// the route specific cookie is returned in a signed query params
	c := r.PathPrefix(dashboardPath + "/callback").Subrouter()
	c.Path("/").Handler(httputil.HandlerFunc(p.Callback)).Methods(http.MethodGet)

	// Programmatic API handlers and middleware
	a := r.PathPrefix(dashboardPath + "/api").Subrouter()
	// login api handler generates a user-navigable login url to authenticate
	a.Path("/v1/login").Handler(httputil.HandlerFunc(p.ProgrammaticLogin)).
		Queries(urlutil.QueryRedirectURI, "").
		Methods(http.MethodGet)

	a.Path("/v1/device_auth").Handler(httputil.HandlerFunc(p.DeviceAuthLogin)).
		Methods(http.MethodGet, http.MethodPost)

	return r
}

// SignOut clears the local session and redirects the request to the sign out url.
// It's the responsibility of the authenticate service to revoke the remote session and clear
// the authenticate service's session state.
func (p *Proxy) SignOut(w http.ResponseWriter, r *http.Request) error {
	state := p.state.Load()

	var redirectURL *url.URL
	signOutURL, err := p.currentOptions.Load().GetSignOutRedirectURL()
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
		Path: "/.pomerium/sign_out",
	})
	q := dashboardURL.Query()
	if redirectURL != nil {
		q.Set(urlutil.QueryRedirectURI, redirectURL.String())
	}
	dashboardURL.RawQuery = q.Encode()

	state.sessionStore.ClearSession(w, r)
	httputil.Redirect(w, r, urlutil.NewSignedURL(state.sharedKey, dashboardURL).String(), http.StatusFound)
	return nil
}

func (p *Proxy) userInfo(w http.ResponseWriter, r *http.Request) error {
	data, err := p.getUserInfoData(r)
	if err != nil {
		return err
	}
	handlers.UserInfo(data).ServeHTTP(w, r)
	return nil
}

func (p *Proxy) deviceEnrolled(w http.ResponseWriter, r *http.Request) error {
	data, err := p.getUserInfoData(r)
	if err != nil {
		return err
	}
	handlers.DeviceEnrolled(data).ServeHTTP(w, r)
	return nil
}

// Callback handles the result of a successful call to the authenticate service
// and is responsible setting per-route sessions.
func (p *Proxy) Callback(w http.ResponseWriter, r *http.Request) error {
	return p.state.Load().authenticateFlow.Callback(w, r)
}

// ProgrammaticLogin returns a signed url that can be used to login
// using the authenticate service.
func (p *Proxy) ProgrammaticLogin(w http.ResponseWriter, r *http.Request) error {
	state := p.state.Load()
	options := p.currentOptions.Load()

	redirectURI, err := urlutil.ParseAndValidateURL(r.FormValue(urlutil.QueryRedirectURI))
	if err != nil {
		return httputil.NewError(http.StatusBadRequest, err)
	}

	if !urlutil.IsRedirectAllowed(redirectURI, state.programmaticRedirectDomainWhitelist) {
		return httputil.NewError(http.StatusBadRequest, errors.New("invalid redirect uri"))
	}

	idp, err := options.GetIdentityProviderForRequestURL(urlutil.GetAbsoluteURL(r).String())
	if err != nil {
		return httputil.NewError(http.StatusInternalServerError, err)
	}

	callbackURI := urlutil.GetAbsoluteURL(r)
	callbackURI.Path = dashboardPath + "/callback/"
	q := url.Values{}
	q.Set(urlutil.QueryCallbackURI, callbackURI.String())
	q.Set(urlutil.QueryIsProgrammatic, "true")

	rawURL, err := state.authenticateFlow.AuthenticateSignInURL(
		r.Context(), q, redirectURI, idp.GetId())
	if err != nil {
		return httputil.NewError(http.StatusInternalServerError, err)
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, rawURL)
	return nil
}

func (p *Proxy) DeviceAuthLogin(w http.ResponseWriter, r *http.Request) error {
	state := p.state.Load()
	options := p.currentOptions.Load()

	params := url.Values{}
	routeUri := urlutil.GetAbsoluteURL(r)
	params.Set(urlutil.QueryDeviceAuthRouteURI, routeUri.String())

	idp, err := options.GetIdentityProviderForRequestURL(routeUri.String())
	if err != nil {
		return httputil.NewError(http.StatusInternalServerError, err)
	}
	params.Set(urlutil.QueryIdentityProviderID, idp.Id)

	if retryToken := r.FormValue(urlutil.QueryDeviceAuthRetryToken); retryToken != "" {
		params.Set(urlutil.QueryDeviceAuthRetryToken, retryToken)
	}

	return state.authenticateFlow.AuthenticateDeviceCode(w, r, params)
}

// jwtAssertion returns the current request's JWT assertion (rfc7519#section-10.3.1).
func (p *Proxy) jwtAssertion(w http.ResponseWriter, r *http.Request) error {
	rawAssertionJWT := r.Header.Get(httputil.HeaderPomeriumJWTAssertion)
	if rawAssertionJWT == "" {
		return httputil.NewError(http.StatusNotFound, errors.New("jwt not found"))
	}

	assertionJWT, err := jwt.ParseSigned(rawAssertionJWT)
	if err != nil {
		return httputil.NewError(http.StatusNotFound, errors.New("jwt not found"))
	}

	var dst struct {
		Subject string `json:"sub"`
	}
	if assertionJWT.UnsafeClaimsWithoutVerification(&dst) != nil || dst.Subject == "" {
		return httputil.NewError(http.StatusUnauthorized, errors.New("jwt not found"))
	}

	w.Header().Set("Content-Type", "application/jwt")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, rawAssertionJWT)
	return nil
}
