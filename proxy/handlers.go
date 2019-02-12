package proxy // import "github.com/pomerium/pomerium/proxy"

import (
	"encoding/base64"
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
	// ErrUserNotAuthorized is set when user is not authorized to access a resource
	ErrUserNotAuthorized = errors.New("user not authorized")
)

var securityHeaders = map[string]string{
	"X-Content-Type-Options": "nosniff",
	"X-Frame-Options":        "SAMEORIGIN",
	"X-XSS-Protection":       "1; mode=block",
}

// StateParameter holds the redirect id along with the session id.
type StateParameter struct {
	SessionID   string `json:"session_id"`
	RedirectURI string `json:"redirect_uri"`
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

	// serve the middleware and mux
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
// with a 404 otherwise, to avoid spurious and confusing authenticate attempts when a browser
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
	fullURL := p.GetSignOutURL(p.AuthenticateURL, redirectURL)
	http.Redirect(w, r, fullURL.String(), http.StatusFound)
}

// OAuthStart begins the authenticate flow, encrypting the redirect url
// in a request to the provider's sign in endpoint.
func (p *Proxy) OAuthStart(w http.ResponseWriter, r *http.Request) {
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
	signinURL := p.GetSignInURL(p.AuthenticateURL, callbackURL, encryptedState)
	log.FromRequest(r).Info().Str("SigninURL", signinURL.String()).Msg("proxy: oauth start")
	// redirect the user to the authenticate provider along with the encrypted state which
	// contains a redirect uri pointing back to the proxy
	http.Redirect(w, r, signinURL.String(), http.StatusFound)
}

// OAuthCallback validates the cookie sent back from the authenticate service. This function will
// contain an error, or it will contain a `code`; the code can be used to fetch an access token, and
// other metadata, from the authenticator.
// finish the oauth cycle
func (p *Proxy) OAuthCallback(w http.ResponseWriter, r *http.Request) {
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
	rr, err := p.AuthenticateClient.Redeem(r.Form.Get("code"))
	if err != nil {
		log.FromRequest(r).Error().Err(err).Msg("error redeeming authorization code")
		httputil.ErrorResponse(w, r, "Internal error", http.StatusInternalServerError)
		return
	}

	encryptedState := r.Form.Get("state")
	log.Warn().
		Str("encryptedState", encryptedState).
		Msg("OK")

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
	err = p.sessionStore.SaveSession(w, r, &sessions.SessionState{
		AccessToken:      rr.AccessToken,
		RefreshToken:     rr.RefreshToken,
		IDToken:          rr.IDToken,
		User:             rr.User,
		Email:            rr.Email,
		RefreshDeadline:  (rr.Expiry).Truncate(time.Second),
		LifetimeDeadline: extendDeadline(p.CookieLifetimeTTL),
		ValidDeadline:    extendDeadline(p.CookieExpire),
	})
	if err != nil {
		log.FromRequest(r).Error().Msg("error saving session")
		httputil.ErrorResponse(w, r, "Error saving session", http.StatusInternalServerError)
		return
	}

	log.FromRequest(r).Info().
		Str("code", r.Form.Get("code")).
		Str("state", r.Form.Get("state")).
		Str("RefreshToken", rr.RefreshToken).
		Str("session", rr.AccessToken).
		Str("RedirectURI", stateParameter.RedirectURI).
		Msg("session")

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
// or starting the authenticate service for validation if not.
func (p *Proxy) Proxy(w http.ResponseWriter, r *http.Request) {
	err := p.Authenticate(w, r)
	// If the authenticate is not successful we proceed to start the OAuth Flow with
	// OAuthStart. If successful, we proceed to proxy to the configured upstream.
	if err != nil {
		switch err {
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

	// 				! 				!					!
	// todo(bdd): 	! Authorization service goes here   !
	//				! 				!					!

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
		log.FromRequest(r).Info().Msg("proxy.Authenticate: lifetime expired, restarting")
		return sessions.ErrLifetimeExpired
	}
	if session.RefreshPeriodExpired() {
		// AccessToken's usually expire after 60 or so minutes. If offline_access scope is set, a
		// refresh token (which doesn't change) can be used to request a new access-token. If access
		// is revoked by identity provider, or no refresh token is set request will return an error
		accessToken, expiry, err := p.AuthenticateClient.Refresh(session.RefreshToken)
		if err != nil {
			log.FromRequest(r).Warn().
				Str("RefreshToken", session.RefreshToken).
				Str("AccessToken", session.AccessToken).
				Msg("proxy.Authenticate: refresh failure")
			return err
		}
		session.AccessToken = accessToken
		session.RefreshDeadline = expiry
		log.FromRequest(r).Info().Msg("proxy.Authenticate:  refresh success")
	}

	err = p.sessionStore.SaveSession(w, r, session)
	if err != nil {
		return err
	}
	// pass user & user-email details to client applications
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
