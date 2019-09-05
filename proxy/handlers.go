package proxy // import "github.com/pomerium/pomerium/proxy"

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/pomerium/pomerium/internal/config"
	"github.com/pomerium/pomerium/internal/cryptutil"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/middleware"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/internal/templates"
	"github.com/pomerium/pomerium/internal/urlutil"
)

// StateParameter holds the redirect id along with the session id.
type StateParameter struct {
	SessionID   string `json:"session_id"`
	RedirectURI string `json:"redirect_uri"`
}

// Handler returns the proxy service's ServeMux
func (p *Proxy) Handler() http.Handler {
	// validation middleware chain
	validate := middleware.NewChain()
	validate = validate.Append(middleware.ValidateHost(func(host string) bool {
		_, ok := p.routeConfigs[host]
		return ok
	}))
	mux := http.NewServeMux()
	mux.HandleFunc("/robots.txt", p.RobotsTxt)
	mux.HandleFunc("/.pomerium", p.UserDashboard)
	mux.HandleFunc("/.pomerium/impersonate", p.Impersonate) // POST
	mux.HandleFunc("/.pomerium/sign_out", p.SignOut)
	// handlers with validation
	mux.Handle("/.pomerium/callback", validate.ThenFunc(p.AuthenticateCallback))
	mux.Handle("/.pomerium/refresh", validate.ThenFunc(p.ForceRefresh))
	mux.Handle("/", validate.ThenFunc(p.Proxy))
	return mux
}

// RobotsTxt sets the User-Agent header in the response to be "Disallow"
func (p *Proxy) RobotsTxt(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "User-agent: *\nDisallow: /")
}

// SignOut redirects the request to the sign out url. It's the responsibility
// of the authenticate service to revoke the remote session and clear
// the local session state.
func (p *Proxy) SignOut(w http.ResponseWriter, r *http.Request) {
	redirectURL := &url.URL{Scheme: "https", Host: r.Host, Path: "/"}
	switch r.Method {
	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			httputil.ErrorResponse(w, r, err)
			return
		}
		uri, err := urlutil.ParseAndValidateURL(r.Form.Get("redirect_uri"))
		if err == nil && uri.String() != "" {
			redirectURL = uri
		}
	default:
		uri, err := urlutil.ParseAndValidateURL(r.URL.Query().Get("redirect_uri"))
		if err == nil && uri.String() != "" {
			redirectURL = uri
		}
	}
	http.Redirect(w, r, p.GetSignOutURL(p.authenticateURL, redirectURL).String(), http.StatusFound)
}

// OAuthStart begins the authenticate flow, encrypting the redirect url
// in a request to the provider's sign in endpoint.
func (p *Proxy) OAuthStart(w http.ResponseWriter, r *http.Request) {
	state := &StateParameter{
		SessionID:   fmt.Sprintf("%x", cryptutil.GenerateKey()),
		RedirectURI: r.URL.String(),
	}

	// Encrypt CSRF + redirect_uri and store in csrf session. Validated on callback.
	csrfState, err := p.cipher.Marshal(state)
	if err != nil {
		httputil.ErrorResponse(w, r, err)
		return
	}
	p.csrfStore.SetCSRF(w, r, csrfState)

	paramState, err := p.cipher.Marshal(state)
	if err != nil {
		httputil.ErrorResponse(w, r, err)
		return
	}

	// Sanity check. The encrypted payload of local and remote state should
	// never match as each encryption round uses a cryptographic nonce.
	// if paramState == csrfState {
	// 	httputil.ErrorResponse(w, r, httputil.Error("encrypted state should not match", http.StatusBadRequest, nil))
	// 	return
	// }

	signinURL := p.GetSignInURL(p.authenticateURL, p.GetRedirectURL(r.Host), paramState)

	// Redirect the user to the authenticate service along with the encrypted
	// state which contains a redirect uri back to the proxy and a nonce
	http.Redirect(w, r, signinURL.String(), http.StatusFound)
}

// AuthenticateCallback checks the state parameter to make sure it matches the
// local csrf state then redirects the user back to the original intended route.
func (p *Proxy) AuthenticateCallback(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		httputil.ErrorResponse(w, r, err)
		return
	}

	// Encrypted CSRF passed from authenticate service
	remoteStateEncrypted := r.Form.Get("state")
	var remoteStatePlain StateParameter
	if err := p.cipher.Unmarshal(remoteStateEncrypted, &remoteStatePlain); err != nil {
		httputil.ErrorResponse(w, r, err)
		return
	}

	c, err := p.csrfStore.GetCSRF(r)
	if err != nil {
		httputil.ErrorResponse(w, r, err)
		return
	}
	p.csrfStore.ClearCSRF(w, r)

	localStateEncrypted := c.Value
	var localStatePlain StateParameter
	err = p.cipher.Unmarshal(localStateEncrypted, &localStatePlain)
	if err != nil {
		httputil.ErrorResponse(w, r, err)
		return
	}

	// assert no nonce reuse
	if remoteStateEncrypted == localStateEncrypted {
		p.sessionStore.ClearSession(w, r)
		httputil.ErrorResponse(w, r,
			httputil.Error("local and remote state", http.StatusBadRequest,
				fmt.Errorf("possible nonce-reuse / replay attack")))
		return
	}

	// Decrypted remote and local state struct (inc. nonce) must match
	if remoteStatePlain.SessionID != localStatePlain.SessionID {
		p.sessionStore.ClearSession(w, r)
		httputil.ErrorResponse(w, r, httputil.Error("CSRF mismatch", http.StatusBadRequest, nil))
		return
	}

	// This is the redirect back to the original requested application
	http.Redirect(w, r, remoteStatePlain.RedirectURI, http.StatusFound)
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

func (p *Proxy) loadExistingSession(r *http.Request) (*sessions.State, error) {
	s, err := p.sessionStore.LoadSession(r)
	if err != nil {
		return nil, fmt.Errorf("proxy: invalid session: %w", err)
	}
	if err := s.Valid(); err != nil {
		return nil, fmt.Errorf("proxy: invalid state: %w", err)
	}
	return s, nil
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

	s, err := p.loadExistingSession(r)
	if err != nil {
		log.Debug().Str("cause", err.Error()).Msg("proxy: bad authN session, redirecting")
		p.OAuthStart(w, r)
		return
	}
	authorized, err := p.AuthorizeClient.Authorize(r.Context(), r.Host, s)
	if err != nil {
		httputil.ErrorResponse(w, r, err)
		return
	} else if !authorized {
		httputil.ErrorResponse(w, r, httputil.Error(fmt.Sprintf("%s is not authorized for this route", s.Email), http.StatusForbidden, nil))
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
	session, err := p.loadExistingSession(r)
	if err != nil {
		log.Debug().Str("cause", err.Error()).Msg("proxy: bad authN session, redirecting")
		p.OAuthStart(w, r)
		return
	}

	redirectURL := &url.URL{Scheme: "https", Host: r.Host, Path: "/.pomerium/sign_out"}
	isAdmin, err := p.AuthorizeClient.IsAdmin(r.Context(), session)
	if err != nil {
		httputil.ErrorResponse(w, r, err)
		return
	}

	// CSRF value used to mitigate replay attacks.
	csrf := &StateParameter{SessionID: fmt.Sprintf("%x", cryptutil.GenerateKey())}
	csrfCookie, err := p.cipher.Marshal(csrf)
	if err != nil {
		httputil.ErrorResponse(w, r, err)
		return
	}
	p.csrfStore.SetCSRF(w, r, csrfCookie)

	t := struct {
		Email           string
		User            string
		Groups          []string
		RefreshDeadline string
		SignoutURL      string

		IsAdmin          bool
		ImpersonateEmail string
		ImpersonateGroup string
		CSRF             string
	}{
		Email:            session.Email,
		User:             session.User,
		Groups:           session.Groups,
		RefreshDeadline:  time.Until(session.RefreshDeadline).Round(time.Second).String(),
		SignoutURL:       p.GetSignOutURL(p.authenticateURL, redirectURL).String(),
		IsAdmin:          isAdmin,
		ImpersonateEmail: session.ImpersonateEmail,
		ImpersonateGroup: strings.Join(session.ImpersonateGroups, ","),
		CSRF:             csrf.SessionID,
	}
	templates.New().ExecuteTemplate(w, "dashboard.html", t)
}

// ForceRefresh redeems and extends an existing authenticated oidc session with
// the underlying identity provider. All session details including groups,
// timeouts, will be renewed.
func (p *Proxy) ForceRefresh(w http.ResponseWriter, r *http.Request) {
	session, err := p.loadExistingSession(r)
	if err != nil {
		log.Debug().Str("cause", err.Error()).Msg("proxy: bad authN session, redirecting")
		p.OAuthStart(w, r)
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
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			httputil.ErrorResponse(w, r, err)
			return
		}
		session, err := p.loadExistingSession(r)
		if err != nil {
			log.Debug().Str("cause", err.Error()).Msg("proxy: bad authN session, redirecting")
			p.OAuthStart(w, r)
			return
		}
		isAdmin, err := p.AuthorizeClient.IsAdmin(r.Context(), session)
		if err != nil || !isAdmin {
			httputil.ErrorResponse(w, r, httputil.Error(fmt.Sprintf("%s is not an administrator", session.Email), http.StatusForbidden, err))
			return
		}
		// CSRF check -- did this request originate from our form?
		c, err := p.csrfStore.GetCSRF(r)
		if err != nil {
			httputil.ErrorResponse(w, r, err)
			return
		}
		p.csrfStore.ClearCSRF(w, r)
		encryptedCSRF := c.Value
		var decryptedCSRF StateParameter
		if err = p.cipher.Unmarshal(encryptedCSRF, decryptedCSRF); err != nil {
			httputil.ErrorResponse(w, r, err)
			return
		}
		if decryptedCSRF.SessionID != r.FormValue("csrf") {
			httputil.ErrorResponse(w, r, httputil.Error("CSRF mismatch", http.StatusBadRequest, nil))
			return
		}

		// OK to impersonation
		session.ImpersonateEmail = r.FormValue("email")
		session.ImpersonateGroups = strings.Split(r.FormValue("group"), ",")

		if err := p.sessionStore.SaveSession(w, r, session); err != nil {
			httputil.ErrorResponse(w, r, err)
			return
		}
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

// GetRedirectURL returns the redirect url for a single reverse proxy host. HTTPS is set explicitly.
func (p *Proxy) GetRedirectURL(host string) *url.URL {
	u := p.redirectURL
	u.Scheme = "https"
	u.Host = host
	return u
}

// signRedirectURL takes a redirect url string and timestamp and returns the base64
// encoded HMAC result.
func (p *Proxy) signRedirectURL(rawRedirect string, timestamp time.Time) string {
	data := []byte(fmt.Sprint(rawRedirect, timestamp.Unix()))
	h := cryptutil.Hash(p.SharedKey, data)
	return base64.URLEncoding.EncodeToString(h)
}

// GetSignInURL with typical oauth parameters
func (p *Proxy) GetSignInURL(authenticateURL, redirectURL *url.URL, state string) *url.URL {
	a := authenticateURL.ResolveReference(&url.URL{Path: "/sign_in"})
	now := time.Now()
	rawRedirect := redirectURL.String()
	params, _ := url.ParseQuery(a.RawQuery) // handled by ServeMux
	params.Set("redirect_uri", rawRedirect)
	params.Set("shared_secret", p.SharedKey)
	params.Set("response_type", "code")
	params.Add("state", state)
	params.Set("ts", fmt.Sprint(now.Unix()))
	params.Set("sig", p.signRedirectURL(rawRedirect, now))
	a.RawQuery = params.Encode()
	return a
}

// GetSignOutURL creates and returns the sign out URL, given a redirectURL
func (p *Proxy) GetSignOutURL(authenticateURL, redirectURL *url.URL) *url.URL {
	a := authenticateURL.ResolveReference(&url.URL{Path: "/sign_out"})
	now := time.Now()
	rawRedirect := redirectURL.String()
	params, _ := url.ParseQuery(a.RawQuery) // handled by ServeMux
	params.Add("redirect_uri", rawRedirect)
	params.Set("ts", fmt.Sprint(now.Unix()))
	params.Set("sig", p.signRedirectURL(rawRedirect, now))
	a.RawQuery = params.Encode()
	return a
}
