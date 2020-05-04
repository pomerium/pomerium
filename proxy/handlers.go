package proxy

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"

	"github.com/gorilla/mux"
	"github.com/pomerium/csrf"

	"github.com/pomerium/pomerium/internal/cryptutil"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/middleware"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/internal/urlutil"
)

// registerDashboardHandlers returns the proxy service's ServeMux
func (p *Proxy) registerDashboardHandlers(r *mux.Router) *mux.Router {
	h := r.PathPrefix(dashboardURL).Subrouter()
	h.Use(middleware.SetHeaders(httputil.HeadersContentSecurityPolicy))
	// 1. Retrieve the user session and add it to the request context
	h.Use(sessions.RetrieveSession(p.sessionStore))
	// 2. AuthN - Verify the user is authenticated. Set email, group, & id headers
	h.Use(p.AuthenticateSession)
	// 3. Enforce CSRF protections for any non-idempotent http method
	h.Use(csrf.Protect(
		p.cookieSecret,
		csrf.Secure(p.cookieOptions.Secure),
		csrf.CookieName(fmt.Sprintf("%s_csrf", p.cookieOptions.Name)),
		csrf.ErrorHandler(httputil.HandlerFunc(httputil.CSRFFailureHandler)),
	))
	// dashboard endpoints can be used by user's to view, or modify their session
	h.Path("/").Handler(httputil.HandlerFunc(p.UserDashboard)).Methods(http.MethodGet)
	h.Path("/sign_in").HandlerFunc(p.SignIn).Methods(http.MethodGet)
	h.Path("/sign_out").HandlerFunc(p.SignOut).Methods(http.MethodGet, http.MethodPost)
	// admin endpoints authorization is also delegated to authorizer service
	admin := h.PathPrefix("/admin").Subrouter()
	admin.Path("/impersonate").Handler(httputil.HandlerFunc(p.Impersonate)).Methods(http.MethodPost)

	// Authenticate service callback handlers and middleware
	// callback used to set route-scoped session and redirect back to destination
	// only accept signed requests (hmac) from other trusted pomerium services
	c := r.PathPrefix(dashboardURL + "/callback").Subrouter()
	c.Use(middleware.ValidateSignature(p.SharedKey))

	c.Path("/").
		Handler(httputil.HandlerFunc(p.ProgrammaticCallback)).
		Methods(http.MethodGet).
		Queries(urlutil.QueryIsProgrammatic, "true")

	c.Path("/").Handler(httputil.HandlerFunc(p.Callback)).Methods(http.MethodGet)
	// Programmatic API handlers and middleware
	a := r.PathPrefix(dashboardURL + "/api").Subrouter()
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

// SignIn redircts /.pomerium/sign_in to the authentication server.
func (p *Proxy) SignIn(w http.ResponseWriter, r *http.Request) {
	redirectURL := &url.URL{Scheme: "https", Host: r.Host, Path: "/"}
	if uri, err := urlutil.ParseAndValidateURL(r.FormValue(urlutil.QueryRedirectURI)); err == nil && uri.String() != "" {
		redirectURL = uri
	}

	signinURL := *p.authenticateSigninURL
	q := signinURL.Query()
	q.Set(urlutil.QueryRedirectURI, redirectURL.String())
	signinURL.RawQuery = q.Encode()

	p.sessionStore.ClearSession(w, r)
	httputil.Redirect(w, r, urlutil.NewSignedURL(p.SharedKey, &signinURL).String(), http.StatusFound)
}

// SignOut redirects the request to the sign out url. It's the responsibility
// of the authenticate service to revoke the remote session and clear
// the local session state.
func (p *Proxy) SignOut(w http.ResponseWriter, r *http.Request) {
	redirectURL := &url.URL{Scheme: "https", Host: r.Host, Path: "/"}
	if uri, err := urlutil.ParseAndValidateURL(r.FormValue(urlutil.QueryRedirectURI)); err == nil && uri.String() != "" {
		redirectURL = uri
	}

	signoutURL := *p.authenticateSignoutURL
	q := signoutURL.Query()
	q.Set(urlutil.QueryRedirectURI, redirectURL.String())
	signoutURL.RawQuery = q.Encode()

	p.sessionStore.ClearSession(w, r)
	httputil.Redirect(w, r, urlutil.NewSignedURL(p.SharedKey, &signoutURL).String(), http.StatusFound)
}

// UserDashboard lets users investigate, and refresh their current session.
// It also contains certain administrative actions like user impersonation.
//
// Nota bene: This endpoint does authentication, not authorization.
func (p *Proxy) UserDashboard(w http.ResponseWriter, r *http.Request) error {
	jwt, err := sessions.FromContext(r.Context())
	if err != nil {
		return err
	}
	var s sessions.State
	if err := p.encoder.Unmarshal([]byte(jwt), &s); err != nil {
		return httputil.NewError(http.StatusBadRequest, err)
	}

	p.templates.ExecuteTemplate(w, "dashboard.html", map[string]interface{}{
		"Session":           s,
		"csrfField":         csrf.TemplateField(r),
		"ImpersonateAction": urlutil.QueryImpersonateAction,
		"ImpersonateEmail":  urlutil.QueryImpersonateEmail,
		"ImpersonateGroups": urlutil.QueryImpersonateGroups,
	})
	return nil
}

// Impersonate takes the result of a form and adds user impersonation details
// to the user's current user sessions state if the user is currently an
// administrative user. Requests are redirected back to the user dashboard.
func (p *Proxy) Impersonate(w http.ResponseWriter, r *http.Request) error {
	redirectURL := urlutil.GetAbsoluteURL(r)
	redirectURL.Path = dashboardURL // redirect back to the dashboard
	signinURL := *p.authenticateSigninURL
	q := signinURL.Query()
	q.Set(urlutil.QueryRedirectURI, redirectURL.String())
	q.Set(urlutil.QueryImpersonateAction, r.FormValue(urlutil.QueryImpersonateAction))
	q.Set(urlutil.QueryImpersonateEmail, r.FormValue(urlutil.QueryImpersonateEmail))
	q.Set(urlutil.QueryImpersonateGroups, r.FormValue(urlutil.QueryImpersonateGroups))
	signinURL.RawQuery = q.Encode()
	httputil.Redirect(w, r, urlutil.NewSignedURL(p.SharedKey, &signinURL).String(), http.StatusFound)
	return nil
}

// Callback handles the result of a successful call to the authenticate service
// and is responsible setting returned per-route session.
func (p *Proxy) Callback(w http.ResponseWriter, r *http.Request) error {
	redirectURLString := r.FormValue(urlutil.QueryRedirectURI)
	encryptedSession := r.FormValue(urlutil.QuerySessionEncrypted)

	if _, err := p.saveCallbackSession(w, r, encryptedSession); err != nil {
		return httputil.NewError(http.StatusBadRequest, err)
	}
	httputil.Redirect(w, r, redirectURLString, http.StatusFound)
	return nil
}

// saveCallbackSession takes an encrypted per-route session token, and decrypts
// it using the shared service key, then stores it the local session store.
func (p *Proxy) saveCallbackSession(w http.ResponseWriter, r *http.Request, enctoken string) ([]byte, error) {
	// 1. extract the base64 encoded and encrypted JWT from query params
	encryptedJWT, err := base64.URLEncoding.DecodeString(enctoken)
	if err != nil {
		return nil, fmt.Errorf("proxy: malfromed callback token: %w", err)
	}
	// 2. decrypt the JWT using the cipher using the _shared_ secret key
	rawJWT, err := cryptutil.Decrypt(p.sharedCipher, encryptedJWT, nil)
	if err != nil {
		return nil, fmt.Errorf("proxy: callback token decrypt error: %w", err)
	}
	// 3. Save the decrypted JWT to the session store directly as a string, without resigning
	if err = p.sessionStore.SaveSession(w, r, rawJWT); err != nil {
		return nil, fmt.Errorf("proxy: callback session save failure: %w", err)
	}
	return rawJWT, nil
}

// ProgrammaticLogin returns a signed url that can be used to login
// using the authenticate service.
func (p *Proxy) ProgrammaticLogin(w http.ResponseWriter, r *http.Request) error {
	redirectURI, err := urlutil.ParseAndValidateURL(r.FormValue(urlutil.QueryRedirectURI))
	if err != nil {
		return httputil.NewError(http.StatusBadRequest, err)
	}
	signinURL := *p.authenticateSigninURL
	callbackURI := urlutil.GetAbsoluteURL(r)
	callbackURI.Path = dashboardURL + "/callback/"
	q := signinURL.Query()
	q.Set(urlutil.QueryCallbackURI, callbackURI.String())
	q.Set(urlutil.QueryRedirectURI, redirectURI.String())
	q.Set(urlutil.QueryIsProgrammatic, "true")
	signinURL.RawQuery = q.Encode()
	response := urlutil.NewSignedURL(p.SharedKey, &signinURL).String()

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(response))
	return nil
}

// ProgrammaticCallback handles a successful call to the authenticate service.
// In addition to returning the individual route session (JWT) it also returns
// the refresh token.
func (p *Proxy) ProgrammaticCallback(w http.ResponseWriter, r *http.Request) error {
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

	q := redirectURL.Query()
	q.Set(urlutil.QueryPomeriumJWT, string(rawJWT))
	q.Set(urlutil.QueryRefreshToken, r.FormValue(urlutil.QueryRefreshToken))
	redirectURL.RawQuery = q.Encode()
	httputil.Redirect(w, r, redirectURL.String(), http.StatusFound)
	return nil
}
