package proxy // import "github.com/pomerium/pomerium/proxy"

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
	"github.com/pomerium/pomerium/internal/templates"
	"github.com/pomerium/pomerium/internal/urlutil"
)

// registerDashboardHandlers returns the proxy service's ServeMux
func (p *Proxy) registerDashboardHandlers(r *mux.Router) *mux.Router {
	h := r.PathPrefix(dashboardURL).Subrouter()
	// 1. Retrieve the user session and add it to the request context
	h.Use(sessions.RetrieveSession(p.sessionStore))
	// 2. AuthN - Verify the user is authenticated. Set email, group, & id headers
	h.Use(p.AuthenticateSession)
	// 3. Enforce CSRF protections for any non-idempotent http method
	h.Use(csrf.Protect(
		p.cookieSecret,
		csrf.Secure(p.cookieOptions.Secure),
		csrf.CookieName(fmt.Sprintf("%s_csrf", p.cookieOptions.Name)),
		csrf.ErrorHandler(http.HandlerFunc(httputil.CSRFFailureHandler)),
	))
	// dashboard endpoints can be used by user's to view, or modify their session
	h.HandleFunc("/", p.UserDashboard).Methods(http.MethodGet)
	h.HandleFunc("/impersonate", p.Impersonate).Methods(http.MethodPost)
	h.HandleFunc("/sign_out", p.SignOut).Methods(http.MethodGet, http.MethodPost)

	// Authenticate service callback handlers and middleware
	// callback used to set route-scoped session and redirect back to destination
	// only accept signed requests (hmac) from other trusted pomerium services
	c := r.PathPrefix(dashboardURL + "/callback").Subrouter()
	c.Use(middleware.ValidateSignature(p.SharedKey))

	c.Path("/").HandlerFunc(p.ProgrammaticCallback).Methods(http.MethodGet).
		Queries(urlutil.QueryIsProgrammatic, "true")

	c.Path("/").HandlerFunc(p.Callback).Methods(http.MethodGet)
	// Programmatic API handlers and middleware
	a := r.PathPrefix(dashboardURL + "/api").Subrouter()
	// login api handler generates a user-navigable login url to authenticate
	a.HandleFunc("/v1/login", p.ProgrammaticLogin).
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
// Nota bene: This endpoint does authentication, not authorization.
func (p *Proxy) UserDashboard(w http.ResponseWriter, r *http.Request) {
	session, err := sessions.FromContext(r.Context())
	if err != nil {
		httputil.ErrorResponse(w, r, err)
		return
	}

	isAdmin, err := p.AuthorizeClient.IsAdmin(r.Context(), session)
	if err != nil {
		httputil.ErrorResponse(w, r, err)
		return
	}

	templates.New().ExecuteTemplate(w, "dashboard.html", map[string]interface{}{
		"Session":   session,
		"IsAdmin":   isAdmin,
		"csrfField": csrf.TemplateField(r),
	})
}

// Impersonate takes the result of a form and adds user impersonation details
// to the user's current user sessions state if the user is currently an
// administrative user. Requests are redirected back to the user dashboard.
func (p *Proxy) Impersonate(w http.ResponseWriter, r *http.Request) {
	session, err := sessions.FromContext(r.Context())
	if err != nil {
		httputil.ErrorResponse(w, r, err)
		return
	}
	isAdmin, err := p.AuthorizeClient.IsAdmin(r.Context(), session)
	if err != nil || !isAdmin {
		errStr := fmt.Sprintf("%s is not an administrator", session.RequestEmail())
		httpErr := httputil.Error(errStr, http.StatusForbidden, err)
		httputil.ErrorResponse(w, r, httpErr)
		return
	}
	// OK to impersonation
	redirectURL := urlutil.GetAbsoluteURL(r)
	redirectURL.Path = dashboardURL // redirect back to the dashboard
	signinURL := *p.authenticateSigninURL
	q := signinURL.Query()
	q.Set(urlutil.QueryRedirectURI, redirectURL.String())
	q.Set(urlutil.QueryImpersonateEmail, r.FormValue("email"))
	q.Set(urlutil.QueryImpersonateGroups, r.FormValue("group"))
	signinURL.RawQuery = q.Encode()
	httputil.Redirect(w, r, urlutil.NewSignedURL(p.SharedKey, &signinURL).String(), http.StatusFound)
}

// Callback handles the result of a successful call to the authenticate service
// and is responsible setting returned per-route session.
func (p *Proxy) Callback(w http.ResponseWriter, r *http.Request) {
	redirectURLString := r.FormValue(urlutil.QueryRedirectURI)
	encryptedSession := r.FormValue(urlutil.QuerySessionEncrypted)

	if _, err := p.saveCallbackSession(w, r, encryptedSession); err != nil {
		httputil.ErrorResponse(w, r, httputil.Error(err.Error(), http.StatusBadRequest, err))
		return
	}

	httputil.Redirect(w, r, redirectURLString, http.StatusFound)
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
func (p *Proxy) ProgrammaticLogin(w http.ResponseWriter, r *http.Request) {
	redirectURI, err := urlutil.ParseAndValidateURL(r.FormValue(urlutil.QueryRedirectURI))
	if err != nil {
		httputil.ErrorResponse(w, r, httputil.Error("malformed redirect uri", http.StatusBadRequest, err))
		return
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
}

// ProgrammaticCallback handles a successful call to the authenticate service.
// In addition to returning the individual route session (JWT) it also returns
// the refresh token.
func (p *Proxy) ProgrammaticCallback(w http.ResponseWriter, r *http.Request) {
	redirectURLString := r.FormValue(urlutil.QueryRedirectURI)
	encryptedSession := r.FormValue(urlutil.QuerySessionEncrypted)

	redirectURL, err := urlutil.ParseAndValidateURL(redirectURLString)
	if err != nil {
		httputil.ErrorResponse(w, r, httputil.Error("malformed redirect uri", http.StatusBadRequest, err))
		return
	}

	rawJWT, err := p.saveCallbackSession(w, r, encryptedSession)
	if err != nil {
		httputil.ErrorResponse(w, r, httputil.Error(err.Error(), http.StatusBadRequest, err))
		return
	}

	q := redirectURL.Query()
	q.Set(urlutil.QueryPomeriumJWT, string(rawJWT))
	q.Set(urlutil.QueryRefreshToken, r.FormValue(urlutil.QueryRefreshToken))
	redirectURL.RawQuery = q.Encode()

	httputil.Redirect(w, r, redirectURL.String(), http.StatusFound)
}
