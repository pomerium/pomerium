package proxy

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/gorilla/mux"

	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/middleware"
	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/pkg/cryptutil"
)

// registerDashboardHandlers returns the proxy service's ServeMux
func (p *Proxy) registerDashboardHandlers(r *mux.Router) *mux.Router {
	h := r.PathPrefix(dashboardPath).Subrouter()
	h.Use(middleware.SetHeaders(httputil.HeadersContentSecurityPolicy))

	// special pomerium endpoints for users to view their session
	h.Path("/").HandlerFunc(p.userInfo).Methods(http.MethodGet)
	h.Path("/sign_out").HandlerFunc(p.SignOut).Methods(http.MethodGet, http.MethodPost)
	h.Path("/jwt").Handler(httputil.HandlerFunc(p.jwtAssertion)).Methods(http.MethodGet)

	// called following authenticate auth flow to grab a new or existing session
	// the route specific cookie is returned in a signed query params
	c := r.PathPrefix(dashboardPath + "/callback").Subrouter()
	c.Use(func(h http.Handler) http.Handler {
		return middleware.ValidateSignature(p.state.Load().sharedKey)(h)
	})
	c.Path("/").Handler(httputil.HandlerFunc(p.Callback)).Methods(http.MethodGet)

	// Programmatic API handlers and middleware
	a := r.PathPrefix(dashboardPath + "/api").Subrouter()
	// login api handler generates a user-navigable login url to authenticate
	a.Path("/v1/login").Handler(httputil.HandlerFunc(p.ProgrammaticLogin)).
		Queries(urlutil.QueryRedirectURI, "").
		Methods(http.MethodGet)

	return r
}

// RobotsTxt sets the User-Agent header in the response to be "Disallow"
func (p *Proxy) RobotsTxt(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "User-agent: *\nDisallow: /")
}

// SignOut clears the local session and redirects the request to the sign out url.
// It's the responsibility of the authenticate service to revoke the remote session and clear
// the authenticate service's session state.
func (p *Proxy) SignOut(w http.ResponseWriter, r *http.Request) {
	state := p.state.Load()

	redirectURL := &url.URL{Scheme: "https", Host: r.Host, Path: "/"}
	if sru := p.currentOptions.Load().SignOutRedirectURL; sru != nil {
		redirectURL = sru
	}
	if uri, err := urlutil.ParseAndValidateURL(r.FormValue(urlutil.QueryRedirectURI)); err == nil && uri.String() != "" {
		redirectURL = uri
	}

	dashboardURL := *state.authenticateDashboardURL
	q := dashboardURL.Query()
	q.Set(urlutil.QueryRedirectURI, redirectURL.String())
	dashboardURL.RawQuery = q.Encode()

	state.sessionStore.ClearSession(w, r)
	httputil.Redirect(w, r, urlutil.NewSignedURL(state.sharedKey, &dashboardURL).String(), http.StatusFound)
}

func (p *Proxy) userInfo(w http.ResponseWriter, r *http.Request) {
	state := p.state.Load()

	redirectURL := urlutil.GetAbsoluteURL(r).String()
	if ref := r.Header.Get(httputil.HeaderReferrer); ref != "" {
		redirectURL = ref
	}

	uri := state.authenticateDashboardURL.ResolveReference(&url.URL{
		RawQuery: url.Values{
			urlutil.QueryRedirectURI: {redirectURL},
		}.Encode(),
	})
	uri = urlutil.NewSignedURL(state.sharedKey, uri).Sign()
	httputil.Redirect(w, r, uri.String(), http.StatusFound)
}

// Callback handles the result of a successful call to the authenticate service
// and is responsible setting per-route sessions.
func (p *Proxy) Callback(w http.ResponseWriter, r *http.Request) error {
	redirectURLString := r.FormValue(urlutil.QueryRedirectURI)
	encryptedSession := r.FormValue(urlutil.QuerySessionEncrypted)

	redirectURL, err := urlutil.ParseAndValidateURL(redirectURLString)
	if err != nil {
		return httputil.NewError(http.StatusBadRequest, err)
	}

	rawJWT, err := p.saveCallbackSession(w, r, encryptedSession)
	if err != nil {
		return httputil.NewError(http.StatusBadRequest, err)
	}

	// if programmatic, encode the session jwt as a query param
	if isProgrammatic := r.FormValue(urlutil.QueryIsProgrammatic); isProgrammatic == "true" {
		q := redirectURL.Query()
		q.Set(urlutil.QueryPomeriumJWT, string(rawJWT))
		redirectURL.RawQuery = q.Encode()
	}
	httputil.Redirect(w, r, redirectURL.String(), http.StatusFound)
	return nil
}

// saveCallbackSession takes an encrypted per-route session token, decrypts
// it using the shared service key, then stores it the local session store.
func (p *Proxy) saveCallbackSession(w http.ResponseWriter, r *http.Request, enctoken string) ([]byte, error) {
	state := p.state.Load()

	// 1. extract the base64 encoded and encrypted JWT from query params
	encryptedJWT, err := base64.URLEncoding.DecodeString(enctoken)
	if err != nil {
		return nil, fmt.Errorf("proxy: malfromed callback token: %w", err)
	}
	// 2. decrypt the JWT using the cipher using the _shared_ secret key
	rawJWT, err := cryptutil.Decrypt(state.sharedCipher, encryptedJWT, nil)
	if err != nil {
		return nil, fmt.Errorf("proxy: callback token decrypt error: %w", err)
	}
	// 3. Save the decrypted JWT to the session store directly as a string, without resigning
	if err = state.sessionStore.SaveSession(w, r, rawJWT); err != nil {
		return nil, fmt.Errorf("proxy: callback session save failure: %w", err)
	}
	return rawJWT, nil
}

// ProgrammaticLogin returns a signed url that can be used to login
// using the authenticate service.
func (p *Proxy) ProgrammaticLogin(w http.ResponseWriter, r *http.Request) error {
	state := p.state.Load()

	redirectURI, err := urlutil.ParseAndValidateURL(r.FormValue(urlutil.QueryRedirectURI))
	if err != nil {
		return httputil.NewError(http.StatusBadRequest, err)
	}
	signinURL := *state.authenticateSigninURL
	callbackURI := urlutil.GetAbsoluteURL(r)
	callbackURI.Path = dashboardPath + "/callback/"
	q := signinURL.Query()
	q.Set(urlutil.QueryCallbackURI, callbackURI.String())
	q.Set(urlutil.QueryRedirectURI, redirectURI.String())
	q.Set(urlutil.QueryIsProgrammatic, "true")
	signinURL.RawQuery = q.Encode()
	response := urlutil.NewSignedURL(state.sharedKey, &signinURL).String()

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, response)
	return nil
}

// jwtAssertion returns the current request's JWT assertion (rfc7519#section-10.3.1).
func (p *Proxy) jwtAssertion(w http.ResponseWriter, r *http.Request) error {
	assertionJWT := r.Header.Get(httputil.HeaderPomeriumJWTAssertion)
	if assertionJWT == "" {
		return httputil.NewError(http.StatusNotFound, errors.New("jwt not found"))
	}
	w.Header().Set("Content-Type", "application/jwt")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, assertionJWT)
	return nil
}
