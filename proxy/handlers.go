package proxy // import "github.com/pomerium/pomerium/proxy"

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/pomerium/pomerium/internal/cryptutil"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/middleware"
	"github.com/pomerium/pomerium/internal/policy"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/internal/templates"
)

// StateParameter holds the redirect id along with the session id.
type StateParameter struct {
	SessionID   string `json:"session_id"`
	RedirectURI string `json:"redirect_uri"`
}

// Handler returns a http handler for a Proxy
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
	mux.HandleFunc("/.pomerium/sign_out", p.SignOutCallback)
	// handlers handlers with validation
	mux.Handle("/.pomerium/callback", validate.ThenFunc(p.OAuthCallback))
	mux.Handle("/.pomerium/refresh", validate.ThenFunc(p.Refresh))
	mux.Handle("/", validate.ThenFunc(p.Proxy))
	return mux
}

// RobotsTxt sets the User-Agent header in the response to be "Disallow"
func (p *Proxy) RobotsTxt(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "User-agent: *\nDisallow: /")
}

// SignOutCallback redirects the request to the sign out url. It's the responsibility
// of the authenticate service to revoke the remote session and clear
// the local session state.
func (p *Proxy) SignOutCallback(w http.ResponseWriter, r *http.Request) {
	redirectURL := &url.URL{Scheme: "https", Host: r.Host, Path: "/"}
	http.Redirect(w, r, redirectURL.String(), http.StatusFound)
}

// OAuthStart begins the authenticate flow, encrypting the redirect url
// in a request to the provider's sign in endpoint.
func (p *Proxy) OAuthStart(w http.ResponseWriter, r *http.Request) {
	requestURI := r.URL.String()
	callbackURL := p.GetRedirectURL(r.Host)

	// CSRF value used to mitigate replay attacks.
	state := &StateParameter{
		SessionID:   fmt.Sprintf("%x", cryptutil.GenerateKey()),
		RedirectURI: requestURI,
	}

	// Encrypt, and save CSRF state. Will be checked on callback.
	localState, err := p.cipher.Marshal(state)
	if err != nil {
		log.FromRequest(r).Error().Err(err).Msg("proxy: failed to marshal csrf")
		httputil.ErrorResponse(w, r, err.Error(), http.StatusInternalServerError)
		return
	}
	p.csrfStore.SetCSRF(w, r, localState)

	// Though the plaintext payload is identical, we re-encrypt which will
	// create a different cipher text using another nonce
	remoteState, err := p.cipher.Marshal(state)
	if err != nil {
		log.FromRequest(r).Error().Err(err).Msg("proxy: failed to encrypt cookie")
		httputil.ErrorResponse(w, r, err.Error(), http.StatusInternalServerError)
		return
	}

	// Sanity check. The encrypted payload of local and remote state should
	// never match as each encryption round uses a cryptographic nonce.
	//
	// todo(bdd): since this should nearly (1/(2^32*2^32)) never happen should
	// we panic as a failure most likely means the rands entropy source is failing?
	if remoteState == localState {
		p.sessionStore.ClearSession(w, r)
		log.FromRequest(r).Error().Msg("proxy: encrypted state should not match")
		httputil.ErrorResponse(w, r, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	signinURL := p.GetSignInURL(p.AuthenticateURL, callbackURL, remoteState)
	log.FromRequest(r).Debug().Str("SigninURL", signinURL.String()).Msg("proxy: oauth start")

	// Redirect the user to the authenticate service along with the encrypted
	// state which contains a redirect uri back to the proxy and a nonce
	http.Redirect(w, r, signinURL.String(), http.StatusFound)
}

// OAuthCallback validates the cookie sent back from the authenticate service. This function will
// contain an error, or it will contain a `code`; the code can be used to fetch an access token, and
// other metadata, from the authenticator.
// finish the oauth cycle
func (p *Proxy) OAuthCallback(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		log.FromRequest(r).Error().Err(err).Msg("proxy: failed parsing request form")
		httputil.ErrorResponse(w, r, err.Error(), http.StatusInternalServerError)
		return
	}
	errorString := r.Form.Get("error")
	if errorString != "" {
		httputil.ErrorResponse(w, r, errorString, http.StatusForbidden)
		return
	}

	// Encrypted CSRF passed from authenticate service
	remoteStateEncrypted := r.Form.Get("state")
	remoteStatePlain := new(StateParameter)
	err = p.cipher.Unmarshal(remoteStateEncrypted, remoteStatePlain)
	if err != nil {
		log.FromRequest(r).Error().Err(err).Msg("proxy: could not unmarshal state")
		httputil.ErrorResponse(w, r, "Internal error", http.StatusInternalServerError)
		return
	}

	// Encrypted CSRF from session storage
	c, err := p.csrfStore.GetCSRF(r)
	if err != nil {
		log.FromRequest(r).Error().Err(err).Msg("proxy: failed parsing csrf cookie")
		httputil.ErrorResponse(w, r, err.Error(), http.StatusBadRequest)
		return
	}
	p.csrfStore.ClearCSRF(w, r)
	localStateEncrypted := c.Value
	localStatePlain := new(StateParameter)
	err = p.cipher.Unmarshal(localStateEncrypted, localStatePlain)
	if err != nil {
		log.FromRequest(r).Error().Err(err).Msg("proxy: couldn't unmarshal CSRF")
		httputil.ErrorResponse(w, r, "Internal error", http.StatusInternalServerError)
		return
	}

	// If the encrypted value of local and remote state match, reject.
	// Likely a replay attack or nonce-reuse.
	if remoteStateEncrypted == localStateEncrypted {
		p.sessionStore.ClearSession(w, r)
		log.FromRequest(r).Error().Msg("proxy: local and remote state should not match")
		httputil.ErrorResponse(w, r, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	// Decrypted remote and local state struct (inc. nonce) must match
	if remoteStatePlain.SessionID != localStatePlain.SessionID {
		p.sessionStore.ClearSession(w, r)
		log.FromRequest(r).Error().Msg("proxy: CSRF mismatch")
		httputil.ErrorResponse(w, r, "CSRF mismatch", http.StatusBadRequest)
		return
	}

	// This is the redirect back to the original requested application
	http.Redirect(w, r, remoteStatePlain.RedirectURI, http.StatusFound)
}

// shouldSkipAuthentication contains conditions for skipping authentication.
// Conditions should be few in number and have strong justifications.
func (p *Proxy) shouldSkipAuthentication(r *http.Request) bool {
	pol, foundPolicy := p.policy(r)

	if isCORSPreflight(r) && foundPolicy && pol.CORSAllowPreflight {
		log.FromRequest(r).Debug().Msg("proxy: skipping authentication for valid CORS preflight request")
		return true
	}

	if foundPolicy && pol.AllowPublicUnauthenticatedAccess {
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
	if !p.shouldSkipAuthentication(r) {
		session, err := p.sessionStore.LoadSession(r)
		if err != nil {
			switch err {
			case http.ErrNoCookie, sessions.ErrLifetimeExpired, sessions.ErrInvalidSession:
				log.FromRequest(r).Debug().Err(err).Msg("proxy: invalid session")
				p.sessionStore.ClearSession(w, r)
				p.OAuthStart(w, r)
				return
			default:
				log.FromRequest(r).Error().Err(err).Msg("proxy: unexpected error")
				httputil.ErrorResponse(w, r, "An unexpected error occurred", http.StatusInternalServerError)
				return
			}
		}

		if err = p.authenticate(w, r, session); err != nil {
			p.sessionStore.ClearSession(w, r)
			log.Debug().Err(err).Msg("proxy: user unauthenticated")
			httputil.ErrorResponse(w, r, "User unauthenticated", http.StatusForbidden)
			return
		}
		authorized, err := p.AuthorizeClient.Authorize(r.Context(), r.Host, session)
		if err != nil || !authorized {
			log.FromRequest(r).Warn().Err(err).Msg("proxy: user unauthorized")
			httputil.ErrorResponse(w, r, "Access unauthorized", http.StatusForbidden)
			return
		}
	}

	// We have validated the users request and now proxy their request to the provided upstream.
	route, ok := p.router(r)
	if !ok {
		httputil.ErrorResponse(w, r, "unknown route to proxy", http.StatusNotFound)
		return
	}
	route.ServeHTTP(w, r)
}

// UserDashboard lets users investigate, and refresh their current session.
// It also contains certain administrative actions like user impersonation.
// Nota bene: This endpoint does authentication, not authorization.
func (p *Proxy) UserDashboard(w http.ResponseWriter, r *http.Request) {
	session, err := p.sessionStore.LoadSession(r)
	if err != nil {
		log.FromRequest(r).Error().Err(err).Msg("proxy: load session failed")
		httputil.ErrorResponse(w, r, "", http.StatusBadRequest)
		return
	}

	if err := p.authenticate(w, r, session); err != nil {
		log.FromRequest(r).Error().Err(err).Msg("proxy: authenticate failed")
		httputil.ErrorResponse(w, r, "", http.StatusUnauthorized)
		return
	}

	redirectURL := &url.URL{Scheme: "https", Host: r.Host, Path: "/.pomerium/sign_out"}
	isAdmin, err := p.AuthorizeClient.IsAdmin(r.Context(), session)
	if err != nil {
		log.FromRequest(r).Error().Err(err).Msg("proxy: is admin client")
		httputil.ErrorResponse(w, r, "", http.StatusInternalServerError)
		return
	}

	// CSRF value used to mitigate replay attacks.
	csrf := &StateParameter{SessionID: fmt.Sprintf("%x", cryptutil.GenerateKey())}
	csrfCookie, err := p.cipher.Marshal(csrf)
	if err != nil {
		log.FromRequest(r).Error().Err(err).Msg("proxy: failed to marshal csrf")
		httputil.ErrorResponse(w, r, err.Error(), http.StatusInternalServerError)
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
		SignoutURL:       p.GetSignOutURL(p.AuthenticateURL, redirectURL).String(),
		IsAdmin:          isAdmin,
		ImpersonateEmail: session.ImpersonateEmail,
		ImpersonateGroup: strings.Join(session.ImpersonateGroups[:], ","),
		CSRF:             csrf.SessionID,
	}
	templates.New().ExecuteTemplate(w, "dashboard.html", t)
	return
}

// Refresh redeems and extends an existing authenticated oidc session with
// the underlying idenity provider. All session details including groups,
// timeouts, will be renewed.
func (p *Proxy) Refresh(w http.ResponseWriter, r *http.Request) {
	session, err := p.sessionStore.LoadSession(r)
	if err != nil {
		httputil.ErrorResponse(w, r, err.Error(), http.StatusBadRequest)
		return
	}
	iss, err := session.IssuedAt()
	if err != nil {
		log.FromRequest(r).Error().Err(err).Msg("proxy: couldn't get token's create time")
		httputil.ErrorResponse(w, r, "", http.StatusInternalServerError)
		return
	}

	// reject a refresh if it's been less than 5 minutes to prevent a bad actor
	// trying to DOS the identity provider.
	if time.Since(iss) < p.refreshCooldown {
		log.FromRequest(r).Error().Dur("cooldown", p.refreshCooldown).Err(err).Msg("proxy: refresh cooldown")
		httputil.ErrorResponse(w, r,
			fmt.Sprintf("Session must be %v old before refresh", p.refreshCooldown),
			http.StatusBadRequest)
		return
	}

	newSession, err := p.AuthenticateClient.Refresh(r.Context(), session)
	if err != nil {
		log.FromRequest(r).Warn().Err(err).Msg("proxy: refresh failed")
		httputil.ErrorResponse(w, r, err.Error(), http.StatusInternalServerError)
		return
	}
	if err = p.sessionStore.SaveSession(w, r, newSession); err != nil {
		httputil.ErrorResponse(w, r, err.Error(), http.StatusInternalServerError)
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
			log.FromRequest(r).Error().Err(err).Msg("proxy: impersonate form")
			httputil.ErrorResponse(w, r, err.Error(), http.StatusBadRequest)
			return
		}
		session, err := p.sessionStore.LoadSession(r)
		if err != nil {
			log.FromRequest(r).Error().Err(err).Msg("proxy: load session")
			httputil.ErrorResponse(w, r, err.Error(), http.StatusInternalServerError)
			return
		}
		// authorization check -- is this user an admin?
		isAdmin, err := p.AuthorizeClient.IsAdmin(r.Context(), session)
		if err != nil || !isAdmin {
			log.FromRequest(r).Error().Err(err).Msg("proxy: user must be admin to impersonate")
			httputil.ErrorResponse(w, r, "user must be admin to impersonate", http.StatusForbidden)
			return
		}
		// CSRF check -- did this request originate from our form?
		c, err := p.csrfStore.GetCSRF(r)
		if err != nil {
			log.FromRequest(r).Error().Err(err).Msg("proxy: failed parsing csrf cookie")
			httputil.ErrorResponse(w, r, err.Error(), http.StatusBadRequest)
			return
		}
		p.csrfStore.ClearCSRF(w, r)
		encryptedCSRF := c.Value
		decryptedCSRF := new(StateParameter)
		if err = p.cipher.Unmarshal(encryptedCSRF, decryptedCSRF); err != nil {
			log.FromRequest(r).Error().Err(err).Msg("proxy: couldn't unmarshal CSRF")
			httputil.ErrorResponse(w, r, "Internal error", http.StatusInternalServerError)
			return
		}
		if decryptedCSRF.SessionID != r.FormValue("csrf") {
			log.FromRequest(r).Error().Err(err).Msg("proxy: impersonate CSRF mismatch")
			httputil.ErrorResponse(w, r, "CSRF mismatch", http.StatusForbidden)
			return
		}

		// OK to impersonation
		session.ImpersonateEmail = r.FormValue("email")
		session.ImpersonateGroups = strings.Split(r.FormValue("group"), ",")

		if err := p.sessionStore.SaveSession(w, r, session); err != nil {
			log.FromRequest(r).Error().Err(err).Msg("proxy: save session")
			httputil.ErrorResponse(w, r, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	http.Redirect(w, r, "/.pomerium", http.StatusFound)
}

// Authenticate authenticates a request by checking for a session cookie, and validating its expiration,
// clearing the session cookie if it's invalid and returning an error if necessary..
func (p *Proxy) authenticate(w http.ResponseWriter, r *http.Request, session *sessions.SessionState) error {
	if session.RefreshPeriodExpired() {
		session, err := p.AuthenticateClient.Refresh(r.Context(), session)
		if err != nil {
			return fmt.Errorf("proxy: session refresh failed : %v", err)
		}
		err = p.sessionStore.SaveSession(w, r, session)
		if err != nil {
			return fmt.Errorf("proxy: refresh failed : %v", err)
		}
	} else {
		valid, err := p.AuthenticateClient.Validate(r.Context(), session.IDToken)
		if err != nil || !valid {
			return fmt.Errorf("proxy: session valid: %v : %v", valid, err)
		}
	}
	r.Header.Set(HeaderUserID, session.User)
	r.Header.Set(HeaderEmail, session.Email)
	r.Header.Set(HeaderGroups, strings.Join(session.Groups, ","))
	return nil
}

// Handle constructs a route from the given host string and matches it to the provided http.Handler and UpstreamConfig
func (p *Proxy) Handle(host string, handler http.Handler, pol *policy.Policy) {
	p.routeConfigs[host] = &routeConfig{
		mux:    handler,
		policy: *pol,
	}
}

// router attempts to find a route for a request. If a route is successfully matched,
// it returns the route information and a bool value of `true`. If a route can not be matched,
// a nil value for the route and false bool value is returned.
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
func (p *Proxy) policy(r *http.Request) (*policy.Policy, bool) {
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
	params, _ := url.ParseQuery(a.RawQuery)
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
	params, _ := url.ParseQuery(a.RawQuery)
	params.Add("redirect_uri", rawRedirect)
	params.Set("ts", fmt.Sprint(now.Unix()))
	params.Set("sig", p.signRedirectURL(rawRedirect, now))
	a.RawQuery = params.Encode()
	return a
}

func extendDeadline(ttl time.Duration) time.Time {
	return time.Now().Add(ttl).Truncate(time.Second)
}
