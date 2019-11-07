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
	// dashboard subrouter
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
	h.HandleFunc("/", p.UserDashboard).Methods(http.MethodGet)
	h.HandleFunc("/impersonate", p.Impersonate).Methods(http.MethodPost)
	h.HandleFunc("/sign_out", p.SignOut).Methods(http.MethodGet, http.MethodPost)

	// Authenticate service callback handlers and middleware
	c := r.PathPrefix(dashboardURL + "/callback").Subrouter()
	// only accept payloads that have come from a trusted service (hmac)
	c.Use(middleware.ValidateSignature(p.SharedKey))
	c.HandleFunc("/", p.Callback).Queries("redirect_uri", "{redirect_uri}").Methods(http.MethodGet)

	// Programmatic API handlers and middleware
	a := r.PathPrefix(dashboardURL + "/api").Subrouter()
	a.HandleFunc("/v1/login", p.ProgrammaticLogin).Queries("redirect_uri", "{redirect_uri}").Methods(http.MethodGet)

	return r
}

// RobotsTxt sets the User-Agent header in the response to be "Disallow"
func (p *Proxy) RobotsTxt(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "User-agent: *\nDisallow: /")
}

// SignOut redirects the request to the sign out url. It's the responsibility
// of the authenticate service to revoke the remote session and clear
// the local session state.
func (p *Proxy) SignOut(w http.ResponseWriter, r *http.Request) {
	redirectURL := &url.URL{Scheme: "https", Host: r.Host, Path: "/"}
	if uri, err := urlutil.ParseAndValidateURL(r.FormValue("redirect_uri")); err == nil && uri.String() != "" {
		redirectURL = uri
	}
	uri := urlutil.SignedRedirectURL(p.SharedKey, p.authenticateSignoutURL, redirectURL)
	p.sessionStore.ClearSession(w, r)
	http.Redirect(w, r, uri.String(), http.StatusFound)
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
	q := redirectURL.Query()
	q.Add("impersonate_email", r.FormValue("email"))
	q.Add("impersonate_group", r.FormValue("group"))
	redirectURL.RawQuery = q.Encode()
	uri := urlutil.SignedRedirectURL(p.SharedKey, p.authenticateSigninURL, redirectURL).String()
	http.Redirect(w, r, uri, http.StatusFound)
}

func (p *Proxy) registerFwdAuthHandlers() http.Handler {
	r := httputil.NewRouter()
	r.StrictSlash(true)
	r.Use(sessions.RetrieveSession(p.sessionStore))
	r.Handle("/", p.Verify(false)).Queries("uri", "{uri}").Methods(http.MethodGet)
	r.Handle("/verify", p.Verify(true)).Queries("uri", "{uri}").Methods(http.MethodGet)
	return r
}

// Verify checks a user's credentials for an arbitrary host. If the user
// is properly authenticated and is authorized to access the supplied host,
// a `200` http status code is returned. If the user is not authenticated, they
// will be redirected to the authenticate service to sign in with their identity
// provider. If the user is unauthorized, a `401` error is returned.
func (p *Proxy) Verify(verifyOnly bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		uri, err := urlutil.ParseAndValidateURL(r.FormValue("uri"))
		if err != nil || uri.String() == "" {
			httputil.ErrorResponse(w, r, httputil.Error("bad verification uri", http.StatusBadRequest, nil))
			return
		}
		if err := p.authenticate(verifyOnly, w, r); err != nil {
			return
		}
		if err := p.authorize(uri.Host, w, r); err != nil {
			return
		}

		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, fmt.Sprintf("Access to %s is allowed.", uri.Host))
	})

}

// Callback takes a `redirect_uri` query param that has been hmac'd by the
// authenticate service. Embedded in the `redirect_uri` are query-params
// that tell this handler how to set the per-route user session.
// Callback is responsible for redirecting the user back to the intended
// destination URL and path, as well as to clean up any additional query params
// added by the authenticate service.
func (p *Proxy) Callback(w http.ResponseWriter, r *http.Request) {
	redirectURL, err := urlutil.ParseAndValidateURL(r.FormValue("redirect_uri"))
	if err != nil {
		httputil.ErrorResponse(w, r, httputil.Error("malformed redirect_uri", http.StatusBadRequest, err))
		return
	}

	q := redirectURL.Query()
	// 1. extract the base64 encoded and encrypted JWT from redirect_uri's query params
	encryptedJWT, err := base64.URLEncoding.DecodeString(q.Get("pomerium_jwt"))
	if err != nil {
		httputil.ErrorResponse(w, r, httputil.Error("", http.StatusBadRequest, err))
		return
	}
	q.Del("pomerium_jwt")
	q.Del("impersonate_email")
	q.Del("impersonate_group")

	// 2. decrypt the JWT using the cipher using the _shared_ secret key
	rawJWT, err := cryptutil.Decrypt(p.sharedCipher, encryptedJWT, nil)
	if err != nil {
		httputil.ErrorResponse(w, r, httputil.Error("", http.StatusBadRequest, err))
		return
	}
	// 3. Save the decrypted JWT to the session store directly as a string, without resigning
	if err = p.sessionStore.SaveSession(w, r, rawJWT); err != nil {
		httputil.ErrorResponse(w, r, err)
		return
	}

	// if this is a programmatic request, don't strip the tokens before redirect
	if redirectURL.Query().Get("pomerium_programmatic_destination_url") != "" {
		q.Set("pomerium_jwt", string(rawJWT))
	}
	redirectURL.RawQuery = q.Encode()

	http.Redirect(w, r, redirectURL.String(), http.StatusFound)
}

// ProgrammaticLogin returns a signed url that can be used to login
// using the authenticate service.
func (p *Proxy) ProgrammaticLogin(w http.ResponseWriter, r *http.Request) {
	redirectURL, err := urlutil.ParseAndValidateURL(r.FormValue("redirect_uri"))
	if err != nil {
		httputil.ErrorResponse(w, r, httputil.Error("malformed redirect_uri", http.StatusBadRequest, err))
		return
	}
	q := redirectURL.Query()
	q.Add("pomerium_programmatic_destination_url", urlutil.GetAbsoluteURL(r).String())
	redirectURL.RawQuery = q.Encode()
	response := urlutil.SignedRedirectURL(p.SharedKey, p.authenticateSigninURL, redirectURL).String()

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(response))
}
