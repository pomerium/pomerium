package proxy

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"

	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/gorilla/mux"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/handlers"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/middleware"
	"github.com/pomerium/pomerium/internal/urlutil"
)

// registerDashboardHandlers returns the proxy service's ServeMux
func (p *Proxy) registerDashboardHandlers(r *mux.Router, opts *config.Options) *mux.Router {
	h := httputil.DashboardSubrouter(r)
	h.Use(middleware.SetHeaders(httputil.HeadersContentSecurityPolicy))

	// special pomerium endpoints for users to view their session
	h.Path("/").Handler(httputil.HandlerFunc(p.userInfo)).Methods(http.MethodGet)
	h.Path("/device-enrolled").Handler(httputil.HandlerFunc(p.deviceEnrolled))
	if opts.IsRuntimeFlagSet(config.RuntimeFlagPomeriumJWTEndpoint) {
		h.Path("/jwt").Handler(httputil.HandlerFunc(p.jwtAssertion)).Methods(http.MethodGet)
	}
	h.Path("/sign_out").Handler(httputil.HandlerFunc(p.SignOut)).Methods(http.MethodGet, http.MethodPost)
	h.Path("/user").Handler(httputil.HandlerFunc(p.jsonUserInfo)).Methods(http.MethodGet)
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

// jwtAssertion returns the current request's JWT assertion (rfc7519#section-10.3.1).
func (p *Proxy) jwtAssertion(w http.ResponseWriter, r *http.Request) error {
	rawAssertionJWT := r.Header.Get(httputil.HeaderPomeriumJWTAssertion)
	if info := userInfoFromJWT(rawAssertionJWT); info == nil {
		return httputil.NewError(http.StatusNotFound, errors.New("jwt not found"))
	}

	w.Header().Set("Content-Type", "application/jwt")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, rawAssertionJWT)
	return nil
}

// jsonUserInfo serves the same user info as in the Pomerium JWT, but as a plain JSON object.
// Note that this is a subset of the full IdP user info from the main HTML user info page.
func (p *Proxy) jsonUserInfo(w http.ResponseWriter, r *http.Request) error {
	userInfo := userInfoFromJWT(r.Header.Get(httputil.HeaderPomeriumJWTAssertion))
	if userInfo == nil {
		return httputil.NewError(http.StatusNotFound, errors.New("not found"))
	}

	b, err := json.Marshal(userInfo)
	if err != nil {
		return httputil.NewError(http.StatusNotFound, errors.New("not found"))
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(b)
	return nil
}

// userInfoFromJWT extracts user info claims from the Pomerium JWT. Returns nil
// if the JWT could not be parsed or if it does not contain a subject.
func userInfoFromJWT(rawJWT string) map[string]any {
	parsed, err := jwt.ParseSigned(rawJWT)
	if err != nil {
		return nil
	}

	var payload map[string]any
	if parsed.UnsafeClaimsWithoutVerification(&payload) != nil {
		return nil
	} else if sub, ok := payload["sub"].(string); !ok || sub == "" {
		return nil
	}

	// Remove claims pertaining to the JWT itself (not the user info).
	for _, claim := range []string{"iss", "aud", "exp", "iat", "jti"} {
		delete(payload, claim)
	}

	return payload
}
