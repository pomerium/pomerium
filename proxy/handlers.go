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
	// routes
	mux := http.NewServeMux()
	mux.HandleFunc("/favicon.ico", p.Favicon)
	mux.HandleFunc("/robots.txt", p.RobotsTxt)
	mux.HandleFunc("/.pomerium/sign_out", p.SignOut)
	mux.HandleFunc("/.pomerium/callback", p.OAuthCallback)
	mux.HandleFunc("/.pomerium/auth", p.AuthenticateOnly)
	mux.HandleFunc("/", p.Proxy)

	// middleware chain
	c := middleware.NewChain()
	c = c.Append(middleware.Healthcheck("/ping", version.UserAgent()))
	c = c.Append(middleware.NewHandler(log.Logger))
	c = c.Append(middleware.AccessHandler(func(r *http.Request, status, size int, duration time.Duration) {
		middleware.FromRequest(r).Debug().
			Str("method", r.Method).
			Str("url", r.URL.String()).
			Int("status", status).
			Int("size", size).
			Dur("duration", duration).
			Str("pomerium-user", r.Header.Get(HeaderUserID)).
			Str("pomerium-email", r.Header.Get(HeaderEmail)).
			Msg("proxy: request")
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
		mux.ServeHTTP(w, r)
	}))
	return h
}

// RobotsTxt sets the User-Agent header in the response to be "Disallow"
func (p *Proxy) RobotsTxt(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "User-agent: *\nDisallow: /")
}

// Favicon will proxy the request as usual if the user is already authenticated but responds
// with a 404 otherwise, to avoid spurious and confusing authentication attempts when a browser
// automatically requests the favicon on an error page.
func (p *Proxy) Favicon(w http.ResponseWriter, r *http.Request) {
	err := p.Authenticate(w, r)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	p.Proxy(w, r)
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
		httputil.ErrorResponse(w, r, err.Error(), http.StatusInternalServerError)
		return
	}
	p.csrfStore.SetCSRF(w, r, encryptedCSRF)

	// we encrypt this value to be opaque the uri query value
	// this value will be unique since we always use a randomized nonce as part of marshaling
	encryptedState, err := p.cipher.Marshal(state)
	if err != nil {
		log.FromRequest(r).Error().Err(err).Msg("failed to encrypt cookie")
		httputil.ErrorResponse(w, r, err.Error(), http.StatusInternalServerError)
		return
	}

	signinURL := p.authenticateClient.GetSignInURL(callbackURL, encryptedState)
	log.FromRequest(r).Info().Msg("redirecting to begin auth flow")
	http.Redirect(w, r, signinURL.String(), http.StatusFound)
}

// OAuthCallback validates the cookie sent back from the provider, then validates he user
// information, and if authorized, redirects the user back to the original application.
func (p *Proxy) OAuthCallback(w http.ResponseWriter, r *http.Request) {
	// We receive the callback from the SSO Authenticator. This request will either contain an
	// error, or it will contain a `code`; the code can be used to fetch an access token, and
	// other metadata, from the authenticator.
	// finish the oauth cycle
	err := r.ParseForm()
	if err != nil {
		log.FromRequest(r).Error().Err(err).Msg("failed parsing request form")
		httputil.ErrorResponse(w, r, err.Error(), http.StatusInternalServerError)
		return
	}
	errorString := r.Form.Get("error")
	if errorString != "" {
		httputil.ErrorResponse(w, r, errorString, http.StatusForbidden)
		return
	}

	// We begin the process of redeeming the code for an access token.
	session, err := p.redeemCode(r.Host, r.Form.Get("code"))
	if err != nil {
		log.FromRequest(r).Error().Err(err).Msg("error redeeming authorization code")
		httputil.ErrorResponse(w, r, "Internal error", http.StatusInternalServerError)
		return
	}

	encryptedState := r.Form.Get("state")
	stateParameter := &StateParameter{}
	err = p.cipher.Unmarshal(encryptedState, stateParameter)
	if err != nil {
		log.FromRequest(r).Error().Err(err).Msg("could not unmarshal state")
		httputil.ErrorResponse(w, r, "Internal error", http.StatusInternalServerError)
		return
	}

	c, err := p.csrfStore.GetCSRF(r)
	if err != nil {
		log.FromRequest(r).Error().Err(err).Msg("failed parsing csrf cookie")
		httputil.ErrorResponse(w, r, err.Error(), http.StatusBadRequest)
		return
	}
	p.csrfStore.ClearCSRF(w, r)

	encryptedCSRF := c.Value
	csrfParameter := &StateParameter{}
	err = p.cipher.Unmarshal(encryptedCSRF, csrfParameter)
	if err != nil {
		log.FromRequest(r).Error().Err(err).Msg("couldn't unmarshal CSRF")
		httputil.ErrorResponse(w, r, "Internal error", http.StatusInternalServerError)
		return
	}

	if encryptedState == encryptedCSRF {
		log.FromRequest(r).Error().Msg("encrypted state and CSRF should not be equal")
		httputil.ErrorResponse(w, r, "Bad request", http.StatusBadRequest)
		return
	}

	if !reflect.DeepEqual(stateParameter, csrfParameter) {
		log.FromRequest(r).Error().Msg("state and CSRF should be equal")
		httputil.ErrorResponse(w, r, "Bad request", http.StatusBadRequest)
		return
	}

	// We store the session in a cookie and redirect the user back to the application
	err = p.sessionStore.SaveSession(w, r, session)
	if err != nil {
		log.FromRequest(r).Error().Msg("error saving session")
		httputil.ErrorResponse(w, r, "Error saving session", http.StatusInternalServerError)
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
		case ErrUserNotAuthorized:
			//todo(bdd) : custom forbidden page with details and troubleshooting info
			log.FromRequest(r).Debug().Err(err).Msg("proxy: user access forbidden")
			httputil.ErrorResponse(w, r, "You don't have access", http.StatusForbidden)
			return
		case http.ErrNoCookie, sessions.ErrLifetimeExpired, sessions.ErrInvalidSession:
			log.FromRequest(r).Debug().Err(err).Msg("proxy: starting auth flow")
			p.OAuthStart(w, r)
			return
		default:
			log.FromRequest(r).Error().Err(err).Msg("proxy: unexpected error")
			httputil.ErrorResponse(w, r, "An unexpected error occurred", http.StatusInternalServerError)
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
		return err
	}
	if session.LifetimePeriodExpired() {
		return sessions.ErrLifetimeExpired
	} else if session.RefreshPeriodExpired() {
		ok, err := p.authenticateClient.RefreshSession(session)
		if err != nil {
			return err
		}
		if !ok {
			return ErrUserNotAuthorized
		}
	} else if session.ValidationPeriodExpired() {
		ok := p.authenticateClient.ValidateSessionState(session)
		if !ok {
			return ErrUserNotAuthorized
		}
	}
	err = p.sessionStore.SaveSession(w, r, session)
	if err != nil {
		return err
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
