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

// SignOut redirects the request to the sign out url. It's the responsibility
// of the authenticate service to revoke the remote session and clear
// the local session state.
func (p *Proxy) SignOut(w http.ResponseWriter, r *http.Request) {
	redirectURL := &url.URL{Scheme: "https", Host: r.Host, Path: "/"}
	switch r.Method {
	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			httputil.ErrorResponse(w, r, &httputil.Error{Code: http.StatusBadRequest})
			return
		}
		uri, err := url.Parse(r.Form.Get("redirect_uri"))
		if err == nil && uri.String() != "" {
			redirectURL = uri
		}
	default:
		uri, err := url.Parse(r.URL.Query().Get("redirect_uri"))
		if err == nil && uri.String() != "" {
			redirectURL = uri
		}
	}
	http.Redirect(w, r, p.GetSignOutURL(p.AuthenticateURL, redirectURL).String(), http.StatusFound)
}

// OAuthStart begins the authenticate flow, encrypting the redirect url
// in a request to the provider's sign in endpoint.
func (p *Proxy) OAuthStart(w http.ResponseWriter, r *http.Request) {

	// create a CSRF value used to mitigate replay attacks.
	state := &StateParameter{
		SessionID:   fmt.Sprintf("%x", cryptutil.GenerateKey()),
		RedirectURI: r.URL.String(),
	}

	// Encrypt, and save CSRF state. Will be checked on callback.
	localState, err := p.cipher.Marshal(state)
	if err != nil {
		log.FromRequest(r).Error().Err(err).Msg("proxy: failed to marshal csrf")
		httpErr := &httputil.Error{Message: err.Error(), Code: http.StatusInternalServerError}
		httputil.ErrorResponse(w, r, httpErr)
		return
	}
	p.csrfStore.SetCSRF(w, r, localState)

	// Though the plaintext payload is identical, we re-encrypt which will
	// create a different cipher text using another nonce
	remoteState, err := p.cipher.Marshal(state)
	if err != nil {
		log.FromRequest(r).Error().Err(err).Msg("proxy: failed to encrypt cookie")
		httpErr := &httputil.Error{Message: err.Error(), Code: http.StatusInternalServerError}
		httputil.ErrorResponse(w, r, httpErr)
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
		httpErr := &httputil.Error{Message: http.StatusText(http.StatusBadRequest), Code: http.StatusBadRequest}
		httputil.ErrorResponse(w, r, httpErr)
		return
	}

	signinURL := p.GetSignInURL(p.AuthenticateURL, p.GetRedirectURL(r.Host), remoteState)
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
	if err := r.ParseForm(); err != nil {
		log.FromRequest(r).Error().Err(err).Msg("proxy: failed parsing request form")
		httpErr := &httputil.Error{Message: err.Error(), Code: http.StatusInternalServerError}
		httputil.ErrorResponse(w, r, httpErr)
		return
	}

	if errorString := r.Form.Get("error"); errorString != "" {
		httpErr := &httputil.Error{Message: errorString, Code: http.StatusBadRequest}
		httputil.ErrorResponse(w, r, httpErr)
		return
	}

	// Encrypted CSRF passed from authenticate service
	remoteStateEncrypted := r.Form.Get("state")
	remoteStatePlain := new(StateParameter)
	if err := p.cipher.Unmarshal(remoteStateEncrypted, remoteStatePlain); err != nil {
		log.FromRequest(r).Error().Err(err).Msg("proxy: could not unmarshal state")
		httpErr := &httputil.Error{Message: "Internal error", Code: http.StatusInternalServerError}
		httputil.ErrorResponse(w, r, httpErr)
		return
	}

	// Encrypted CSRF from session storage
	c, err := p.csrfStore.GetCSRF(r)
	if err != nil {
		log.FromRequest(r).Error().Err(err).Msg("proxy: failed parsing csrf cookie")
		httpErr := &httputil.Error{Message: err.Error(), Code: http.StatusBadRequest}
		httputil.ErrorResponse(w, r, httpErr)
		return
	}
	p.csrfStore.ClearCSRF(w, r)
	localStateEncrypted := c.Value
	localStatePlain := new(StateParameter)
	err = p.cipher.Unmarshal(localStateEncrypted, localStatePlain)
	if err != nil {
		log.FromRequest(r).Error().Err(err).Msg("proxy: couldn't unmarshal CSRF")
		httpErr := &httputil.Error{Message: "Internal error", Code: http.StatusInternalServerError}
		httputil.ErrorResponse(w, r, httpErr)
		return
	}

	// If the encrypted value of local and remote state match, reject.
	// Likely a replay attack or nonce-reuse.
	if remoteStateEncrypted == localStateEncrypted {
		p.sessionStore.ClearSession(w, r)
		log.FromRequest(r).Error().Msg("proxy: local and remote state should not match")
		httpErr := &httputil.Error{Message: http.StatusText(http.StatusBadRequest), Code: http.StatusBadRequest}
		httputil.ErrorResponse(w, r, httpErr)
		return
	}

	// Decrypted remote and local state struct (inc. nonce) must match
	if remoteStatePlain.SessionID != localStatePlain.SessionID {
		p.sessionStore.ClearSession(w, r)
		log.FromRequest(r).Error().Msg("proxy: CSRF mismatch")
		httpErr := &httputil.Error{Message: "CSRF mismatch", Code: http.StatusBadRequest}
		httputil.ErrorResponse(w, r, httpErr)
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

// Proxy authenticates a request, either proxying the request if it is authenticated,
// or starting the authenticate service for validation if not.
func (p *Proxy) Proxy(w http.ResponseWriter, r *http.Request) {
	if !p.shouldSkipAuthentication(r) {
		s, err := p.restStore.LoadSession(r)
		// if authorization bearer token does not exist or fails, use cookie store
		if err != nil || s == nil {
			s, err = p.sessionStore.LoadSession(r)
			if err != nil {
				switch err {
				case http.ErrNoCookie, sessions.ErrLifetimeExpired, sessions.ErrInvalidSession:
					log.FromRequest(r).Debug().Str("cause", err.Error()).Msg("proxy: invalid session, start auth process")
					p.sessionStore.ClearSession(w, r)
					p.OAuthStart(w, r)
					return
				default:
					log.FromRequest(r).Error().Err(err).Msg("proxy: unexpected error")
					httpErr := &httputil.Error{Message: "An unexpected error occurred", Code: http.StatusInternalServerError}
					httputil.ErrorResponse(w, r, httpErr)
					return
				}
			}
		}

		if err = p.authenticate(w, r, s); err != nil {
			p.sessionStore.ClearSession(w, r)
			log.FromRequest(r).Debug().Err(err).Msg("proxy: user unauthenticated")
			httpErr := &httputil.Error{Message: "User unauthenticated", Code: http.StatusForbidden, CanDebug: true}
			httputil.ErrorResponse(w, r, httpErr)
			return
		}
		authorized, err := p.AuthorizeClient.Authorize(r.Context(), r.Host, s)
		if err != nil {
			log.FromRequest(r).Error().Err(err).Msg("proxy: failed authorization")
			httpErr := &httputil.Error{Code: http.StatusInternalServerError}
			httputil.ErrorResponse(w, r, httpErr)
			return
		}

		if !authorized {
			log.FromRequest(r).Warn().Err(err).Msg("proxy: user unauthorized")
			httpErr := &httputil.Error{Code: http.StatusUnauthorized, CanDebug: true}
			httputil.ErrorResponse(w, r, httpErr)
			return
		}
		r.Header.Set(HeaderUserID, s.User)
		r.Header.Set(HeaderEmail, s.RequestEmail())
		r.Header.Set(HeaderGroups, s.RequestGroups())
	}

	// We have validated the users request and now proxy their request to the provided upstream.
	route, ok := p.router(r)
	if !ok {
		httputil.ErrorResponse(w, r, &httputil.Error{Code: http.StatusNotFound})
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
		log.FromRequest(r).Debug().Str("cause", err.Error()).Msg("proxy: no session, redirecting to auth")
		p.sessionStore.ClearSession(w, r)
		p.OAuthStart(w, r)
		return
	}

	if err := p.authenticate(w, r, session); err != nil {
		log.FromRequest(r).Error().Err(err).Msg("proxy: authenticate failed")
		httpErr := &httputil.Error{Code: http.StatusUnauthorized, CanDebug: true}
		httputil.ErrorResponse(w, r, httpErr)
		return
	}

	redirectURL := &url.URL{Scheme: "https", Host: r.Host, Path: "/.pomerium/sign_out"}
	isAdmin, err := p.AuthorizeClient.IsAdmin(r.Context(), session)
	if err != nil {
		log.FromRequest(r).Error().Err(err).Msg("proxy: is admin client")
		httpErr := &httputil.Error{Code: http.StatusInternalServerError}
		httputil.ErrorResponse(w, r, httpErr)
		return
	}

	// CSRF value used to mitigate replay attacks.
	csrf := &StateParameter{SessionID: fmt.Sprintf("%x", cryptutil.GenerateKey())}
	csrfCookie, err := p.cipher.Marshal(csrf)
	if err != nil {
		log.FromRequest(r).Error().Err(err).Msg("proxy: failed to marshal csrf")
		httpErr := &httputil.Error{Code: http.StatusInternalServerError}
		httputil.ErrorResponse(w, r, httpErr)
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
		ImpersonateGroup: strings.Join(session.ImpersonateGroups, ","),
		CSRF:             csrf.SessionID,
	}
	templates.New().ExecuteTemplate(w, "dashboard.html", t)
}

// Refresh redeems and extends an existing authenticated oidc session with
// the underlying identity provider. All session details including groups,
// timeouts, will be renewed.
func (p *Proxy) Refresh(w http.ResponseWriter, r *http.Request) {
	session, err := p.sessionStore.LoadSession(r)
	if err != nil {
		httpErr := &httputil.Error{Message: err.Error(), Code: http.StatusBadRequest}
		httputil.ErrorResponse(w, r, httpErr)
		return
	}
	iss, err := session.IssuedAt()
	if err != nil {
		log.FromRequest(r).Error().Err(err).Msg("proxy: couldn't get token's create time")
		httpErr := &httputil.Error{Code: http.StatusInternalServerError}
		httputil.ErrorResponse(w, r, httpErr)
		return
	}

	// reject a refresh if it's been less than the refresh cooldown to prevent abuse
	if time.Since(iss) < p.refreshCooldown {
		log.FromRequest(r).Error().Dur("cooldown", p.refreshCooldown).Err(err).Msg("proxy: refresh cooldown")
		httpErr := &httputil.Error{
			Message: fmt.Sprintf("Session must be %v old before refresh", p.refreshCooldown),
			Code:    http.StatusBadRequest}
		httputil.ErrorResponse(w, r, httpErr)
		return
	}

	newSession, err := p.AuthenticateClient.Refresh(r.Context(), session)
	if err != nil {
		log.FromRequest(r).Warn().Err(err).Msg("proxy: refresh failed")
		httpErr := &httputil.Error{Message: err.Error(), Code: http.StatusInternalServerError}
		httputil.ErrorResponse(w, r, httpErr)
		return
	}
	if err = p.sessionStore.SaveSession(w, r, newSession); err != nil {
		httpErr := &httputil.Error{Message: err.Error(), Code: http.StatusInternalServerError}
		httputil.ErrorResponse(w, r, httpErr)
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
			httpErr := &httputil.Error{Message: err.Error(), Code: http.StatusBadRequest}
			httputil.ErrorResponse(w, r, httpErr)
			return
		}
		session, err := p.sessionStore.LoadSession(r)
		if err != nil {
			log.FromRequest(r).Error().Err(err).Msg("proxy: load session")
			httpErr := &httputil.Error{Message: err.Error(), Code: http.StatusInternalServerError}
			httputil.ErrorResponse(w, r, httpErr)
			return
		}
		// authorization check -- is this user an admin?
		isAdmin, err := p.AuthorizeClient.IsAdmin(r.Context(), session)
		if err != nil || !isAdmin {
			log.FromRequest(r).Error().Err(err).Msg("proxy: user must be admin to impersonate")
			httpErr := &httputil.Error{
				Message:  fmt.Sprintf("%s must be and administrator", session.Email),
				Code:     http.StatusForbidden,
				CanDebug: true}
			httputil.ErrorResponse(w, r, httpErr)
			return
		}
		// CSRF check -- did this request originate from our form?
		c, err := p.csrfStore.GetCSRF(r)
		if err != nil {
			log.FromRequest(r).Error().Err(err).Msg("proxy: failed parsing csrf cookie")
			httpErr := &httputil.Error{Message: err.Error(), Code: http.StatusBadRequest}
			httputil.ErrorResponse(w, r, httpErr)
			return
		}
		p.csrfStore.ClearCSRF(w, r)
		encryptedCSRF := c.Value
		decryptedCSRF := new(StateParameter)
		if err = p.cipher.Unmarshal(encryptedCSRF, decryptedCSRF); err != nil {
			log.FromRequest(r).Error().Err(err).Msg("proxy: couldn't unmarshal CSRF")
			httpErr := &httputil.Error{Message: "Internal error", Code: http.StatusInternalServerError}
			httputil.ErrorResponse(w, r, httpErr)
			return
		}
		if decryptedCSRF.SessionID != r.FormValue("csrf") {
			log.FromRequest(r).Error().Err(err).Msg("proxy: impersonate CSRF mismatch")
			httpErr := &httputil.Error{Message: "CSRF mismatch", Code: http.StatusForbidden}
			httputil.ErrorResponse(w, r, httpErr)
			return
		}

		// OK to impersonation
		session.ImpersonateEmail = r.FormValue("email")
		session.ImpersonateGroups = strings.Split(r.FormValue("group"), ",")

		if err := p.sessionStore.SaveSession(w, r, session); err != nil {
			log.FromRequest(r).Error().Err(err).Msg("proxy: save session")
			httpErr := &httputil.Error{Message: err.Error(), Code: http.StatusInternalServerError}
			httputil.ErrorResponse(w, r, httpErr)
			return
		}
	}
	http.Redirect(w, r, "/.pomerium", http.StatusFound)
}

// Authenticate authenticates a request by checking for a session cookie, and validating its expiration,
// clearing the session cookie if it's invalid and returning an error if necessary..
func (p *Proxy) authenticate(w http.ResponseWriter, r *http.Request, s *sessions.SessionState) error {
	if s.RefreshPeriodExpired() {
		s, err := p.AuthenticateClient.Refresh(r.Context(), s)
		if err != nil {
			return fmt.Errorf("proxy: session refresh failed : %v", err)
		}
		if err := p.sessionStore.SaveSession(w, r, s); err != nil {
			return fmt.Errorf("proxy: refresh failed : %v", err)
		}
	} else {
		valid, err := p.AuthenticateClient.Validate(r.Context(), s.IDToken)
		if err != nil || !valid {
			return fmt.Errorf("proxy: session validate failed: %v : %v", valid, err)
		}
	}
	return nil
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
