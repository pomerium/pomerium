package proxy // import "github.com/pomerium/pomerium/proxy"

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/pomerium/csrf"

	"github.com/pomerium/pomerium/internal/config"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/middleware"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/internal/templates"
	"github.com/pomerium/pomerium/internal/urlutil"
)

// Handler returns the proxy service's ServeMux
func (p *Proxy) Handler() http.Handler {
	r := httputil.NewRouter().StrictSlash(true)
	r.Use(middleware.ValidateHost(func(host string) bool {
		_, ok := p.routeConfigs[host]
		return ok
	}))
	r.Use(csrf.Protect(
		p.cookieSecret,
		csrf.Path("/"),
		csrf.Domain(p.cookieDomain),
		csrf.CookieName(fmt.Sprintf("%s_csrf", p.cookieName)),
		csrf.ErrorHandler(http.HandlerFunc(httputil.CSRFFailureHandler)),
	))
	r.HandleFunc("/robots.txt", p.RobotsTxt)
	// requires authN not authZ
	r.Use(sessions.RetrieveSession(p.sessionStore))
	r.Use(p.VerifySession)
	r.HandleFunc("/.pomerium/", p.UserDashboard).Methods(http.MethodGet)
	r.HandleFunc("/.pomerium/impersonate", p.Impersonate).Methods(http.MethodPost)
	r.HandleFunc("/.pomerium/sign_out", p.SignOut).Methods(http.MethodGet, http.MethodPost)
	r.HandleFunc("/.pomerium/refresh", p.ForceRefresh).Methods(http.MethodPost)
	r.PathPrefix("/").HandlerFunc(p.Proxy)
	return r
}

// VerifySession is the middleware used to enforce a valid authentication
// session state is attached to the users's request context.
func (p *Proxy) VerifySession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		state, err := sessions.FromContext(r.Context())
		if err != nil {
			log.Debug().Str("cause", err.Error()).Msg("proxy: re-authenticating due to session state error")
			p.authenticate(w, r)
			return
		}
		if err := state.Valid(); err != nil {
			log.Debug().Str("cause", err.Error()).Msg("proxy: re-authenticating due to invalid session")
			p.authenticate(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
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

// Authenticate begins the authenticate flow, encrypting the redirect url
// in a request to the provider's sign in endpoint.
func (p *Proxy) authenticate(w http.ResponseWriter, r *http.Request) {
	uri := urlutil.SignedRedirectURL(p.SharedKey, p.authenticateSigninURL, urlutil.GetAbsoluteURL(r))
	http.Redirect(w, r, uri.String(), http.StatusFound)
}

// shouldSkipAuthentication contains conditions for skipping authentication.
// Conditions should be few in number and have strong justifications.
func (p *Proxy) shouldSkipAuthentication(r *http.Request) bool {
	policy, policyExists := p.policy(r)

	if isCORSPreflight(r) && policyExists && policy.CORSAllowPreflight {
		log.FromRequest(r).Debug().Msg("proxy: skipping authentication for valid CORS preflight request")
		return true
	}

	if policyExists && policy.AllowPublicUnauthenticatedAccess {
		log.FromRequest(r).Debug().Msg("proxy: skipping authentication for public route")
		return true
	}

	return false
}

// isCORSPreflight inspects the request to see if this is a valid CORS preflight request.
// These checks are not exhaustive, because the proxied server should be verifying it as well.
//
// See https://www.html5rocks.com/static/images/cors_server_flowchart.png for more info.
func isCORSPreflight(r *http.Request) bool {
	return r.Method == http.MethodOptions &&
		r.Header.Get("Access-Control-Request-Method") != "" &&
		r.Header.Get("Origin") != ""
}

// Proxy authenticates a request, either proxying the request if it is authenticated,
// or starting the authenticate service for validation if not.
func (p *Proxy) Proxy(w http.ResponseWriter, r *http.Request) {
	route, ok := p.router(r)
	if !ok {
		httputil.ErrorResponse(w, r, httputil.Error("", http.StatusNotFound, nil))
		return
	}

	if p.shouldSkipAuthentication(r) {
		log.FromRequest(r).Debug().Msg("proxy: access control skipped")
		route.ServeHTTP(w, r)
		return
	}
	s, err := sessions.FromContext(r.Context())
	if err != nil || s == nil {
		log.Debug().Err(err).Msg("proxy: couldn't get session from context")
		p.authenticate(w, r)
		return
	}
	authorized, err := p.AuthorizeClient.Authorize(r.Context(), r.Host, s)
	if err != nil {
		httputil.ErrorResponse(w, r, err)
		return
	} else if !authorized {
		httputil.ErrorResponse(w, r, httputil.Error(fmt.Sprintf("%s is not authorized for this route", s.RequestEmail()), http.StatusForbidden, nil))
		return
	}
	r.Header.Set(HeaderUserID, s.User)
	r.Header.Set(HeaderEmail, s.RequestEmail())
	r.Header.Set(HeaderGroups, s.RequestGroups())

	route.ServeHTTP(w, r)
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
		httputil.ErrorResponse(w, r,
			httputil.Error(
				fmt.Sprintf("Session must be %s old before refreshing", p.refreshCooldown),
				http.StatusBadRequest, nil))
		return
	}
	session.ForceRefresh()
	if err = p.sessionStore.SaveSession(w, r, session); err != nil {
		httputil.ErrorResponse(w, r, err)
		return
	}
	http.Redirect(w, r, "/.pomerium", http.StatusFound)
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
		httputil.ErrorResponse(w, r, httputil.Error(fmt.Sprintf("%s is not an administrator", session.RequestEmail()), http.StatusForbidden, err))
		return
	}
	// OK to impersonation
	session.ImpersonateEmail = r.FormValue("email")
	session.ImpersonateGroups = strings.Split(r.FormValue("group"), ",")

	if err := p.sessionStore.SaveSession(w, r, session); err != nil {
		httputil.ErrorResponse(w, r, err)
		return
	}

	http.Redirect(w, r, "/.pomerium", http.StatusFound)
}

// router attempts to find a route for a request. If a route is successfully matched,
// it returns the route information and a bool value of `true`. If a route can
// not be matched, a nil value for the route and false bool value is returned.
func (p *Proxy) router(r *http.Request) (http.Handler, bool) {
	config, ok := p.routeConfigs[r.Host]
	if ok {
		return config.mux, true
	}
	return nil, false
}

// policy attempts to find a policy for a request. If a policy is successfully matched,
// it returns the policy information and a bool value of `true`. If a policy can not be matched,
// a nil value for the policy and false bool value is returned.
func (p *Proxy) policy(r *http.Request) (*config.Policy, bool) {
	config, ok := p.routeConfigs[r.Host]
	if ok {
		return &config.policy, true
	}
	return nil, false
}
