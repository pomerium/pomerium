package proxy // import "github.com/pomerium/pomerium/proxy"

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"time"

	"github.com/pomerium/pomerium/internal/cryptutil"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/middleware"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/internal/version"
)

var (
	//ErrUserNotAuthorized is set when user is not authorized to access a resource
	ErrUserNotAuthorized = errors.New("user not authorized")
)

var securityHeaders = map[string]string{
	"X-Content-Type-Options": "nosniff",
	"X-Frame-Options":        "SAMEORIGIN",
	"X-XSS-Protection":       "1; mode=block",
}

// Handler returns a http handler for an Proxy
func (p *Proxy) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/favicon.ico", p.Favicon)
	mux.HandleFunc("/robots.txt", p.RobotsTxt)
	mux.HandleFunc("/.pomerium/sign_out", p.SignOut)
	mux.HandleFunc("/.pomerium/callback", p.OAuthCallback)
	mux.HandleFunc("/.pomerium/auth", p.AuthenticateOnly)
	mux.HandleFunc("/", p.Proxy)

	// Global middleware, which will be applied to each request in reverse
	// order as applied here (i.e., we want to validate the host _first_ when
	// processing a request)
	var handler http.Handler = mux
	// todo(bdd) : investigate if setting non-overridable headers makes sense
	// handler = p.setResponseHeaderOverrides(handler)

	// Middleware chain
	c := middleware.NewChain()
	c = c.Append(middleware.NewHandler(log.Logger))
	c = c.Append(middleware.AccessHandler(func(r *http.Request, status, size int, duration time.Duration) {
		middleware.FromRequest(r).Info().
			Str("method", r.Method).
			Str("url", r.URL.String()).
			Int("status", status).
			Int("size", size).
			Dur("duration", duration).
			Str("pomerium-user", r.Header.Get(HeaderUserID)).
			Str("pomerium-email", r.Header.Get(HeaderEmail)).
			Msg("request")
	}))
	c = c.Append(middleware.SetHeaders(securityHeaders))
	c = c.Append(middleware.RequireHTTPS)
	c = c.Append(middleware.ForwardedAddrHandler("fwd_ip"))
	c = c.Append(middleware.RemoteAddrHandler("ip"))
	c = c.Append(middleware.UserAgentHandler("user_agent"))
	c = c.Append(middleware.RefererHandler("referer"))
	c = c.Append(middleware.RequestIDHandler("req_id", "Request-Id"))
	c = c.Append(middleware.ValidateHost(p.mux))
	h := c.Then(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip host validation for /ping requests because they hit the LB directly.
		if r.URL.Path == "/ping" {
			p.PingPage(w, r)
			return
		}
		handler.ServeHTTP(w, r)
	}))
	return h
}

// RobotsTxt sets the User-Agent header in the response to be "Disallow"
func (p *Proxy) RobotsTxt(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "User-agent: *\nDisallow: /")
}

// Favicon will proxy the request as usual if the user is already authenticated
// but responds with a 404 otherwise, to avoid spurious and confusing
// authentication attempts when a browser automatically requests the favicon on
// an error page.
func (p *Proxy) Favicon(w http.ResponseWriter, r *http.Request) {
	err := p.Authenticate(w, r)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	p.Proxy(w, r)
}

// PingPage send back a 200 OK response.
func (p *Proxy) PingPage(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "OK")
}

// SignOut redirects the request to the sign out url.
func (p *Proxy) SignOut(w http.ResponseWriter, r *http.Request) {
	p.sessionStore.ClearSession(w, r)
	redirectURL := &url.URL{
		Scheme: "https",
		Host:   r.Host,
		Path:   "/",
	}
	fullURL := p.authenticateClient.GetSignOutURL(redirectURL)
	http.Redirect(w, r, fullURL.String(), http.StatusFound)
}

// ErrorPage renders an error page with a given status code, title, and message.
func (p *Proxy) ErrorPage(w http.ResponseWriter, r *http.Request, code int, title string, message string) {
	w.WriteHeader(code)
	t := struct {
		Code    int
		Title   string
		Message string
		Version string
	}{
		Code:    code,
		Title:   title,
		Message: message,
		Version: version.FullVersion(),
	}
	p.templates.ExecuteTemplate(w, "error.html", t)
}

// OAuthStart begins the authentication flow, encrypting the redirect url
// in a request to the provider's sign in endpoint.
func (p *Proxy) OAuthStart(w http.ResponseWriter, r *http.Request) {
	// The proxy redirects to the authenticator, and provides it with redirectURI (which points
	// back to the sso proxy).
	requestURI := r.URL.String()
	callbackURL := p.GetRedirectURL(r.Host)

	// state prevents cross site forgery and maintain state across the client and server
	state := &StateParameter{
		SessionID:   fmt.Sprintf("%x", cryptutil.GenerateKey()), // nonce
		RedirectURI: requestURI,                                 // where to redirect the user back to
	}

	// we encrypt this value to be opaque the browser cookie
	// this value will be unique since we always use a randomized nonce as part of marshaling
	encryptedCSRF, err := p.cipher.Marshal(state)
	if err != nil {
		log.FromRequest(r).Error().Err(err).Msg("failed to marshal csrf")
		p.ErrorPage(w, r, http.StatusInternalServerError, "Internal Error", err.Error())
		return
	}
	p.csrfStore.SetCSRF(w, r, encryptedCSRF)

	// we encrypt this value to be opaque the uri query value
	// this value will be unique since we always use a randomized nonce as part of marshaling
	encryptedState, err := p.cipher.Marshal(state)
	if err != nil {
		log.FromRequest(r).Error().Err(err).Msg("failed to encrypt cookie")
		p.ErrorPage(w, r, http.StatusInternalServerError, "Internal Error", err.Error())
		return
	}

	signinURL := p.authenticateClient.GetSignInURL(callbackURL, encryptedState)
	log.FromRequest(r).Info().Msg("redirecting to begin auth flow")
	http.Redirect(w, r, signinURL.String(), http.StatusFound)
}

// OAuthCallback validates the cookie sent back from the provider, then validates
// the user information, and if authorized, redirects the user back to the original
// application.
func (p *Proxy) OAuthCallback(w http.ResponseWriter, r *http.Request) {
	// We receive the callback from the SSO Authenticator. This request will either contain an
	// error, or it will contain a `code`; the code can be used to fetch an access token, and
	// other metadata, from the authenticator.
	// finish the oauth cycle
	err := r.ParseForm()
	if err != nil {
		log.FromRequest(r).Error().Err(err).Msg("failed parsing request form")
		p.ErrorPage(w, r, http.StatusInternalServerError, "Internal Error", err.Error())
		return
	}
	errorString := r.Form.Get("error")
	if errorString != "" {
		p.ErrorPage(w, r, http.StatusForbidden, "Permission Denied", errorString)
		return
	}

	// We begin the process of redeeming the code for an access token.
	session, err := p.redeemCode(r.Host, r.Form.Get("code"))
	if err != nil {
		log.FromRequest(r).Error().Err(err).Msg("error redeeming authorization code")
		p.ErrorPage(w, r, http.StatusInternalServerError, "Internal Error", "Internal Error")
		return
	}

	encryptedState := r.Form.Get("state")
	stateParameter := &StateParameter{}
	err = p.cipher.Unmarshal(encryptedState, stateParameter)
	if err != nil {
		log.FromRequest(r).Error().Err(err).Msg("could not unmarshal state")
		p.ErrorPage(w, r, http.StatusInternalServerError, "Internal Error", "Internal Error")
		return
	}

	c, err := p.csrfStore.GetCSRF(r)
	if err != nil {
		log.FromRequest(r).Error().Err(err).Msg("failed parsing csrf cookie")
		p.ErrorPage(w, r, http.StatusBadRequest, "Bad Request", err.Error())
		return
	}
	p.csrfStore.ClearCSRF(w, r)

	encryptedCSRF := c.Value
	csrfParameter := &StateParameter{}
	err = p.cipher.Unmarshal(encryptedCSRF, csrfParameter)
	if err != nil {
		log.FromRequest(r).Error().Err(err).Msg("couldn't unmarshal CSRF")
		p.ErrorPage(w, r, http.StatusInternalServerError, "Internal Error", "Internal Error")
		return
	}

	if encryptedState == encryptedCSRF {
		log.FromRequest(r).Error().Msg("encrypted state and CSRF should not be equal")
		p.ErrorPage(w, r, http.StatusBadRequest, "Bad Request", "Bad Request")
		return
	}

	if !reflect.DeepEqual(stateParameter, csrfParameter) {
		log.FromRequest(r).Error().Msg("state and CSRF should be equal")
		p.ErrorPage(w, r, http.StatusBadRequest, "Bad Request", "Bad Request")
		return
	}

	// We store the session in a cookie and redirect the user back to the application
	err = p.sessionStore.SaveSession(w, r, session)
	if err != nil {
		log.FromRequest(r).Error().Msg("error saving session")
		p.ErrorPage(w, r, http.StatusInternalServerError, "Internal Error", "Internal Error")
		return
	}

	// This is the redirect back to the original requested application
	http.Redirect(w, r, stateParameter.RedirectURI, http.StatusFound)
}

// AuthenticateOnly calls the Authenticate handler.
func (p *Proxy) AuthenticateOnly(w http.ResponseWriter, r *http.Request) {
	err := p.Authenticate(w, r)
	if err != nil {
		http.Error(w, "unauthorized request", http.StatusUnauthorized)
	}
	w.WriteHeader(http.StatusAccepted)
}

// Proxy authenticates a request, either proxying the request if it is authenticated,
// or starting the authentication process if not.
func (p *Proxy) Proxy(w http.ResponseWriter, r *http.Request) {
	// Attempts to validate the user and their cookie.
	err := p.Authenticate(w, r)
	// If the authentication is not successful we proceed to start the OAuth Flow with
	// OAuthStart. If successful, we proceed to proxy to the configured upstream.
	if err != nil {
		switch err {
		case http.ErrNoCookie:
			// No cookie is set, start the oauth flow
			p.OAuthStart(w, r)
			return
		case ErrUserNotAuthorized:
			// We know the user is not authorized for the request, we show them a forbidden page
			p.ErrorPage(w, r, http.StatusForbidden, "Forbidden", "You're not authorized to view this page")
			return
		case sessions.ErrLifetimeExpired:
			// User's lifetime expired, we trigger the start of the oauth flow
			p.OAuthStart(w, r)
			return
		case sessions.ErrInvalidSession:
			// The user session is invalid and we can't decode it.
			// This can happen for a variety of reasons but the most common non-malicious
			// case occurs when the session encoding schema changes. We manage this ux
			// by triggering the start of the oauth flow.
			p.OAuthStart(w, r)
			return
		default:
			log.FromRequest(r).Error().Err(err).Msg("unknown error")
			// We don't know exactly what happened, but authenticating the user failed, show an error
			p.ErrorPage(w, r, http.StatusInternalServerError, "Internal Error", "An unexpected error occurred")
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

// Authenticate authenticates a request by checking for a session cookie, and validating its expiration,
// clearing the session cookie if it's invalid and returning an error if necessary..
func (p *Proxy) Authenticate(w http.ResponseWriter, r *http.Request) (err error) {
	// Clear the session cookie if anything goes wrong.
	defer func() {
		if err != nil {
			p.sessionStore.ClearSession(w, r)
		}
	}()

	session, err := p.sessionStore.LoadSession(r)
	if err != nil {
		// We loaded a cookie but it wasn't valid, clear it, and reject the request
		log.FromRequest(r).Error().Err(err).Msg("error authenticating user")
		return err
	}

	// Lifetime period is the entire duration in which the session is valid.
	// This should be set to something like 14 to 30 days.
	if session.LifetimePeriodExpired() {
		log.FromRequest(r).Warn().Str("user", session.Email).Msg("session lifetime has expired")
		return sessions.ErrLifetimeExpired
	} else if session.RefreshPeriodExpired() {
		// Refresh period is the period in which the access token is valid. This is ultimately
		// controlled by the upstream provider and tends to be around 1 hour.
		ok, err := p.authenticateClient.RefreshSession(session)

		// We failed to refresh the session successfully
		// clear the cookie and reject the request
		if err != nil {
			log.FromRequest(r).Error().Err(err).Str("user", session.Email).Msg("refreshing session failed")
			return err
		}

		if !ok {
			// User is not authorized after refresh
			// clear the cookie and reject the request
			log.FromRequest(r).Error().Str("user", session.Email).Msg("not authorized after refreshing session")
			return ErrUserNotAuthorized
		}

		err = p.sessionStore.SaveSession(w, r, session)
		if err != nil {
			// We refreshed the session successfully, but failed to save it.
			//
			// This could be from failing to encode the session properly.
			// But, we clear the session cookie and reject the request!
			log.FromRequest(r).Error().Err(err).Str("user", session.Email).Msg("could not save refresh session")
			return err
		}
	} else if session.ValidationPeriodExpired() {
		// Validation period has expired, this is the shortest interval we use to
		// check for valid requests. This should be set to something like a minute.
		// This calls up the provider chain to validate this user is still active
		// and hasn't been de-authorized.
		ok := p.authenticateClient.ValidateSessionState(session)
		if !ok {
			// This user is now no longer authorized, or we failed to
			// validate the user.
			// Clear the cookie and reject the request
			log.FromRequest(r).Error().Str("user", session.Email).Msg("no longer authorized after validation period")
			return ErrUserNotAuthorized
		}

		err = p.sessionStore.SaveSession(w, r, session)
		if err != nil {
			// We validated the session successfully, but failed to save it.

			// This could be from failing to encode the session properly.
			// But, we clear the session cookie and reject the request!
			log.FromRequest(r).Error().Err(err).Str("user", session.Email).Msg("could not save validated session")
			return err
		}
	}

	r.Header.Set(HeaderUserID, session.User)
	r.Header.Set(HeaderEmail, session.Email)

	// This user has been OK'd. Allow the request!
	return nil
}

// Handle constructs a route from the given host string and matches it to the provided http.Handler and UpstreamConfig
func (p *Proxy) Handle(host string, handler http.Handler) {
	p.mux[host] = handler
}

// router attempts to find a route for a request. If a route is successfully matched,
// it returns the route information and a bool value of `true`. If a route can not be matched,
// a nil value for the route and false bool value is returned.
func (p *Proxy) router(r *http.Request) (http.Handler, bool) {
	route, ok := p.mux[r.Host]
	if ok {
		return route, true
	}
	return nil, false
}

// GetRedirectURL returns the redirect url for a given Proxy,
// setting the scheme to be https if CookieSecure is true.
func (p *Proxy) GetRedirectURL(host string) *url.URL {
	// TODO: Ensure that we only allow valid upstream hosts in redirect URIs
	u := p.redirectURL
	// Build redirect URI from request host
	if u.Scheme == "" {
		u.Scheme = "https"
	}
	u.Host = host
	return u
}

func (p *Proxy) redeemCode(host, code string) (*sessions.SessionState, error) {
	if code == "" {
		return nil, errors.New("missing code")
	}
	redirectURL := p.GetRedirectURL(host)
	s, err := p.authenticateClient.Redeem(redirectURL.String(), code)
	if err != nil {
		return s, err
	}

	if s.Email == "" {
		return s, errors.New("invalid email address")
	}

	return s, nil
}
