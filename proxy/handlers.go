package proxy // import "github.com/pomerium/pomerium/proxy"

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/pomerium/csrf"

	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/internal/templates"
	"github.com/pomerium/pomerium/internal/urlutil"
)

// registerHelperHandlers returns the proxy service's ServeMux
func (p *Proxy) registerHelperHandlers(r *mux.Router) *mux.Router {
	h := r.PathPrefix(dashboardURL).Subrouter()
	// 1. Retrieve the user session and add it to the request context
	h.Use(sessions.RetrieveSession(p.sessionStore))
	// 2. AuthN - Verify the user is authenticated. Set email, group, & id headers
	h.Use(p.AuthenticateSession)
	// 3. Enforce CSRF protections for any non-idempotent http method
	h.Use(csrf.Protect(
		p.cookieSecret,
		csrf.Path("/"),
		csrf.Domain(p.cookieDomain),
		csrf.CookieName(fmt.Sprintf("%s_csrf", p.cookieName)),
		csrf.ErrorHandler(http.HandlerFunc(httputil.CSRFFailureHandler)),
	))
	h.HandleFunc("/", p.UserDashboard).Methods(http.MethodGet)
	h.HandleFunc("/impersonate", p.Impersonate).Methods(http.MethodPost)
	h.HandleFunc("/sign_out", p.SignOut).Methods(http.MethodGet, http.MethodPost)
	h.HandleFunc("/refresh", p.ForceRefresh).Methods(http.MethodPost)
	h.HandleFunc("/verify", p.Verify).Queries("uri", "{uri}").Methods(http.MethodGet)
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
	//todo(bdd): make sign out redirect a configuration option so that
	// 			admins can set to whatever their corporate homepage is
	redirectURL := &url.URL{Scheme: "https", Host: r.Host, Path: "/"}
	signoutURL := urlutil.SignedRedirectURL(p.SharedKey, p.authenticateSignoutURL, redirectURL)
	templates.New().ExecuteTemplate(w, "dashboard.html", map[string]interface{}{
		"Email":            session.Email,
		"User":             session.User,
		"Groups":           session.Groups,
		"RefreshDeadline":  time.Until(session.RefreshDeadline).Round(time.Second).String(),
		"SignoutURL":       signoutURL.String(),
		"IsAdmin":          isAdmin,
		"ImpersonateEmail": session.ImpersonateEmail,
		"ImpersonateGroup": strings.Join(session.ImpersonateGroups, ","),
		"csrfField":        csrf.TemplateField(r),
	})
}

// ForceRefresh redeems and extends an existing authenticated oidc session with
// the underlying identity provider. All session details including groups,
// timeouts, will be renewed.
func (p *Proxy) ForceRefresh(w http.ResponseWriter, r *http.Request) {
	session, err := sessions.FromContext(r.Context())
	if err != nil {
		httputil.ErrorResponse(w, r, err)
		return
	}
	iss, err := session.IssuedAt()
	if err != nil {
		httputil.ErrorResponse(w, r, err)
		return
	}

	// reject a refresh if it's been less than the refresh cooldown to prevent abuse
	if time.Since(iss) < p.refreshCooldown {
		errStr := fmt.Sprintf("Session must be %s old before refreshing", p.refreshCooldown)
		httpErr := httputil.Error(errStr, http.StatusBadRequest, nil)
		httputil.ErrorResponse(w, r, httpErr)
		return
	}
	session.ForceRefresh()
	if err = p.sessionStore.SaveSession(w, r, session); err != nil {
		httputil.ErrorResponse(w, r, err)
		return
	}
	http.Redirect(w, r, dashboardURL, http.StatusFound)
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
	session.ImpersonateEmail = r.FormValue("email")
	session.ImpersonateGroups = strings.Split(r.FormValue("group"), ",")
	groups := r.FormValue("group")
	if groups != "" {
		session.ImpersonateGroups = strings.Split(groups, ",")
	}
	if err := p.sessionStore.SaveSession(w, r, session); err != nil {
		httputil.ErrorResponse(w, r, err)
		return
	}

	http.Redirect(w, r, dashboardURL, http.StatusFound)
}

// Verify checks a user's credentials for an arbitrary host. If the user is
// properly authenticated and is authorized to access the supplied host,
// a 200 http status code is returned. If the user is not authenticated, they
// will be redirected to the authenticate service to sign in with their identity
// provider. If the user is unauthorized, they will be given a 403 http status.
func (p *Proxy) Verify(w http.ResponseWriter, r *http.Request) {
	uri, err := urlutil.ParseAndValidateURL(r.FormValue("uri"))
	if err != nil || uri.String() == "" {
		httputil.ErrorResponse(w, r, httputil.Error("bad verification uri given", http.StatusBadRequest, nil))
		return
	}

	// attempt to retrieve the user session from the request context, validity
	// of the identity session is asserted by the middleware chain
	s, err := sessions.FromContext(r.Context())
	if err != nil {
		httputil.ErrorResponse(w, r, err)
		return
	}
	// query the authorization service to see if the session's user has
	// the appropriate authorization to access the given hostname
	authorized, err := p.AuthorizeClient.Authorize(r.Context(), uri.Host, s)
	if err != nil {
		httputil.ErrorResponse(w, r, err)
		return
	} else if !authorized {
		errMsg := fmt.Sprintf("%s is not authorized for this route", s.RequestEmail())
		httputil.ErrorResponse(w, r, httputil.Error(errMsg, http.StatusForbidden, nil))
		return
	}
	// check the queryparams to see if this check immediately followed
	// authentication. If so, redirect back to the originally requested hostname.
	if isCallback := r.URL.Query().Get("pomerium-auth-callback"); isCallback == "true" {
		http.Redirect(w, r, uri.String(), http.StatusFound)
		return
	}

	// User is authenticated and authorized for the given host.
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set(HeaderUserID, s.User)
	w.Header().Set(HeaderEmail, s.RequestEmail())
	w.Header().Set(HeaderGroups, s.RequestGroups())
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "%s is authorized for %s.", s.Email, uri.String())
}
