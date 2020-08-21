package proxy

import (
	"encoding/base64"
	"fmt"
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

	// dashboard endpoints can be used by user's to view, or modify their session
	h.Path("/").HandlerFunc(p.UserDashboard).Methods(http.MethodGet)
	h.Path("/sign_out").HandlerFunc(p.SignOut).Methods(http.MethodGet, http.MethodPost)

	// Authenticate service callback handlers and middleware
	// callback used to set route-scoped session and redirect back to destination
	// only accept signed requests (hmac) from other trusted pomerium services
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

// SignOut redirects the request to the sign out url. It's the responsibility
// of the authenticate service to revoke the remote session and clear
// the local session state.
func (p *Proxy) SignOut(w http.ResponseWriter, r *http.Request) {
	state := p.state.Load()

	redirectURL := &url.URL{Scheme: "https", Host: r.Host, Path: "/"}
	if uri, err := urlutil.ParseAndValidateURL(r.FormValue(urlutil.QueryRedirectURI)); err == nil && uri.String() != "" {
		redirectURL = uri
	}

	signoutURL := *state.authenticateSignoutURL
	q := signoutURL.Query()
	q.Set(urlutil.QueryRedirectURI, redirectURL.String())
	signoutURL.RawQuery = q.Encode()

	state.sessionStore.ClearSession(w, r)
	httputil.Redirect(w, r, urlutil.NewSignedURL(state.sharedKey, &signoutURL).String(), http.StatusFound)
}

// UserDashboard redirects to the authenticate dashboard.
func (p *Proxy) UserDashboard(w http.ResponseWriter, r *http.Request) {
	state := p.state.Load()

	redirectURL := urlutil.GetAbsoluteURL(r).String()
	if ref := r.Header.Get(httputil.HeaderReferrer); ref != "" {
		redirectURL = ref
	}

	url := state.authenticateDashboardURL.ResolveReference(&url.URL{
		RawQuery: url.Values{
			urlutil.QueryRedirectURI: {redirectURL},
		}.Encode(),
	})
	httputil.Redirect(w, r, url.String(), http.StatusFound)
}

// Callback handles the result of a successful call to the authenticate service
// and is responsible setting returned per-route session.
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

// saveCallbackSession takes an encrypted per-route session token, and decrypts
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
	w.Write([]byte(response))
	return nil
}
