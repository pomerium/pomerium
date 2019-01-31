package authenticate // import "github.com/pomerium/pomerium/authenticate"

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
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/internal/version"
)

// securityHeaders corresponds to HTTP response headers related to security.
// https://www.owasp.org/index.php/OWASP_Secure_Headers_Project#tab=Headers
var securityHeaders = map[string]string{
	"Strict-Transport-Security": "max-age=31536000",
	"X-Frame-Options":           "DENY",
	"X-Content-Type-Options":    "nosniff",
	"X-XSS-Protection":          "1; mode=block",
	"Content-Security-Policy": "default-src 'none'; style-src 'self' " +
		"'sha256-pSTVzZsFAqd2U3QYu+BoBDtuJWaPM/+qMy/dBRrhb5Y='; img-src 'self';",
	"Referrer-Policy": "Same-origin",
}

// Handler returns the Http.Handlers for authenticate, callback, and refresh
func (p *Authenticate) Handler() http.Handler {
	// set up our standard middlewares
	stdMiddleware := middleware.NewChain()
	stdMiddleware = stdMiddleware.Append(middleware.Healthcheck("/ping", version.UserAgent()))
	stdMiddleware = stdMiddleware.Append(middleware.NewHandler(log.Logger))
	stdMiddleware = stdMiddleware.Append(middleware.AccessHandler(
		func(r *http.Request, status, size int, duration time.Duration) {
			middleware.FromRequest(r).Debug().
				Str("method", r.Method).
				Str("url", r.URL.String()).
				Int("status", status).
				Int("size", size).
				Dur("duration", duration).
				Msg("authenticate: request")
		}))
	stdMiddleware = stdMiddleware.Append(middleware.SetHeaders(securityHeaders))
	stdMiddleware = stdMiddleware.Append(middleware.ForwardedAddrHandler("fwd_ip"))
	stdMiddleware = stdMiddleware.Append(middleware.RemoteAddrHandler("ip"))
	stdMiddleware = stdMiddleware.Append(middleware.UserAgentHandler("user_agent"))
	stdMiddleware = stdMiddleware.Append(middleware.RefererHandler("referer"))
	stdMiddleware = stdMiddleware.Append(middleware.RequestIDHandler("req_id", "Request-Id"))
	validateSignatureMiddleware := stdMiddleware.Append(
		middleware.ValidateSignature(p.SharedKey),
		middleware.ValidateRedirectURI(p.ProxyRootDomains))

	mux := http.NewServeMux()
	mux.Handle("/robots.txt", stdMiddleware.ThenFunc(p.RobotsTxt))
	// Identity Provider (IdP) callback endpoints and callbacks
	mux.Handle("/start", stdMiddleware.ThenFunc(p.OAuthStart))
	mux.Handle("/oauth2/callback", stdMiddleware.ThenFunc(p.OAuthCallback))
	// authenticate-server endpoints
	mux.Handle("/sign_in", validateSignatureMiddleware.ThenFunc(p.SignIn))
	mux.Handle("/sign_out", validateSignatureMiddleware.ThenFunc(p.SignOut)) // GET POST

	return mux
}

// RobotsTxt handles the /robots.txt route.
func (p *Authenticate) RobotsTxt(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "User-agent: *\nDisallow: /")
}

func (p *Authenticate) authenticate(w http.ResponseWriter, r *http.Request) (*sessions.SessionState, error) {
	session, err := p.sessionStore.LoadSession(r)
	if err != nil {
		log.FromRequest(r).Error().Err(err).Msg("authenticate: failed to load session")
		p.sessionStore.ClearSession(w, r)
		return nil, err
	}

	// if long-lived lifetime has expired, clear session
	if session.LifetimePeriodExpired() {
		log.FromRequest(r).Warn().Msg("authenticate: lifetime expired")
		p.sessionStore.ClearSession(w, r)
		return nil, sessions.ErrLifetimeExpired
	}
	// check if session refresh period is up
	if session.RefreshPeriodExpired() {
		newToken, err := p.provider.Refresh(session.RefreshToken)
		if err != nil {
			log.FromRequest(r).Error().Err(err).Msg("authenticate: failed to refresh session")
			p.sessionStore.ClearSession(w, r)
			return nil, err
		}
		session.AccessToken = newToken.AccessToken
		session.RefreshDeadline = newToken.Expiry
		err = p.sessionStore.SaveSession(w, r, session)
		if err != nil {
			// We refreshed the session successfully, but failed to save it.
			// This could be from failing to encode the session properly.
			// But, we clear the session cookie and reject the request
			log.FromRequest(r).Error().Err(err).Msg("could not save refreshed session")
			p.sessionStore.ClearSession(w, r)
			return nil, err
		}
	} else {
		// The session has not exceeded it's lifetime or requires refresh
		ok, err := p.provider.Validate(session.IDToken)
		if !ok || err != nil {
			log.FromRequest(r).Error().Err(err).Msg("invalid session state")
			p.sessionStore.ClearSession(w, r)
			return nil, httputil.ErrUserNotAuthorized
		}
		err = p.sessionStore.SaveSession(w, r, session)
		if err != nil {
			log.FromRequest(r).Error().Err(err).Msg("failed to save valid session")
			p.sessionStore.ClearSession(w, r)
			return nil, err
		}
	}

	// authenticate really should not be in the business of authorization
	// todo(bdd) : remove when authorization module added
	if !p.Validator(session.Email) {
		log.FromRequest(r).Error().Msg("invalid email user")
		return nil, httputil.ErrUserNotAuthorized
	}
	log.Info().Msg("authenticate")
	return session, nil
}

// SignIn handles the /sign_in endpoint. It attempts to authenticate the user,
// and if the user is not authenticated, it renders a sign in page.
func (p *Authenticate) SignIn(w http.ResponseWriter, r *http.Request) {
	session, err := p.authenticate(w, r)
	switch err {
	case nil:
		// User is authenticated, redirect back to proxy
		p.ProxyOAuthRedirect(w, r, session)
	case http.ErrNoCookie, sessions.ErrLifetimeExpired, sessions.ErrInvalidSession:
		log.Info().Err(err).Msg("authenticate.SignIn : expected failure")
		if err != http.ErrNoCookie {
			p.sessionStore.ClearSession(w, r)
		}
		p.OAuthStart(w, r)

	default:
		log.Error().Err(err).Msg("authenticate: unexpected sign in error")
		httputil.ErrorResponse(w, r, err.Error(), httputil.CodeForError(err))
	}
}

// ProxyOAuthRedirect redirects the user back to proxy's redirection endpoint.
// This workflow corresponds to Section 3.1.2 of the OAuth2 RFC.
// See https://tools.ietf.org/html/rfc6749#section-3.1.2 for more specific information.
func (p *Authenticate) ProxyOAuthRedirect(w http.ResponseWriter, r *http.Request, session *sessions.SessionState) {
	err := r.ParseForm()
	if err != nil {
		httputil.ErrorResponse(w, r, err.Error(), http.StatusInternalServerError)
		return
	}
	// original `state` parameter received from the proxy application.
	state := r.Form.Get("state")
	if state == "" {
		httputil.ErrorResponse(w, r, "no state parameter supplied", http.StatusForbidden)
		return
	}
	// redirect url of proxy-service
	redirectURI := r.Form.Get("redirect_uri")
	if redirectURI == "" {
		httputil.ErrorResponse(w, r, "no redirect_uri parameter supplied", http.StatusForbidden)
		return
	}

	redirectURL, err := url.Parse(redirectURI)
	if err != nil {
		httputil.ErrorResponse(w, r, "malformed redirect_uri parameter passed", http.StatusBadRequest)
		return
	}
	// encrypt session state as json blob
	encrypted, err := sessions.MarshalSession(session, p.cipher)
	if err != nil {
		httputil.ErrorResponse(w, r, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, getAuthCodeRedirectURL(redirectURL, state, string(encrypted)), http.StatusFound)
}

func getAuthCodeRedirectURL(redirectURL *url.URL, state, authCode string) string {
	u, _ := url.Parse(redirectURL.String())
	params, _ := url.ParseQuery(u.RawQuery)
	params.Set("code", authCode)
	params.Set("state", state)

	u.RawQuery = params.Encode()

	if u.Scheme == "" {
		u.Scheme = "https"
	}

	return u.String()
}

// SignOut signs the user out.
func (p *Authenticate) SignOut(w http.ResponseWriter, r *http.Request) {
	redirectURI := r.Form.Get("redirect_uri")
	if r.Method == "GET" {
		p.SignOutPage(w, r, "")
		return
	}

	session, err := p.sessionStore.LoadSession(r)
	switch err {
	case nil:
		break
	case http.ErrNoCookie: // if there's no cookie in the session we can just redirect
		log.Error().Err(err).Msg("authenticate.SignOut : no cookie")
		http.Redirect(w, r, redirectURI, http.StatusFound)
		return
	default:
		// a different error, clear the session cookie and redirect
		log.Error().Err(err).Msg("authenticate.SignOut : error loading cookie session")
		p.sessionStore.ClearSession(w, r)
		http.Redirect(w, r, redirectURI, http.StatusFound)
		return
	}

	err = p.provider.Revoke(session.AccessToken)
	if err != nil {
		log.Error().Err(err).Msg("authenticate.SignOut : error revoking session")
		p.SignOutPage(w, r, "An error occurred during sign out. Please try again.")
		return
	}
	p.sessionStore.ClearSession(w, r)
	http.Redirect(w, r, redirectURI, http.StatusFound)
}

// SignOutPage renders a sign out page with a message
func (p *Authenticate) SignOutPage(w http.ResponseWriter, r *http.Request, message string) {
	// validateRedirectURI middleware already ensures that this is a valid URL
	redirectURI := r.Form.Get("redirect_uri")
	session, err := p.sessionStore.LoadSession(r)
	if err != nil {
		http.Redirect(w, r, redirectURI, http.StatusFound)
		return
	}

	signature := r.Form.Get("sig")
	timestamp := r.Form.Get("ts")
	destinationURL, err := url.Parse(redirectURI)

	// An error message indicates that an internal server error occurred
	if message != "" || err != nil {
		log.Error().Err(err).Msg("authenticate.SignOutPage")
		w.WriteHeader(http.StatusInternalServerError)
	}

	t := struct {
		Redirect    string
		Signature   string
		Timestamp   string
		Message     string
		Destination string
		Email       string
		Version     string
	}{
		Redirect:    redirectURI,
		Signature:   signature,
		Timestamp:   timestamp,
		Message:     message,
		Destination: destinationURL.Host,
		Email:       session.Email,
		Version:     version.FullVersion(),
	}
	p.templates.ExecuteTemplate(w, "sign_out.html", t)
}

// OAuthStart starts the authenticate process by redirecting to the provider. It provides a
// `redirectURI`, allowing the provider to redirect back to the sso proxy after authenticate.
func (p *Authenticate) OAuthStart(w http.ResponseWriter, r *http.Request) {
	authRedirectURL, err := url.Parse(r.URL.Query().Get("redirect_uri"))
	if err != nil {
		httputil.ErrorResponse(w, r, "Invalid redirect parameter", http.StatusBadRequest)
		return
	}
	authRedirectURL = p.RedirectURL.ResolveReference(r.URL)

	nonce := fmt.Sprintf("%x", cryptutil.GenerateKey())
	p.csrfStore.SetCSRF(w, r, nonce)

	// verify redirect uri is from the root domain
	if !middleware.ValidRedirectURI(authRedirectURL.String(), p.ProxyRootDomains) {
		httputil.ErrorResponse(w, r, "Invalid redirect parameter", http.StatusBadRequest)
		return
	}
	// verify proxy url is from the root domain
	proxyRedirectURL, err := url.Parse(authRedirectURL.Query().Get("redirect_uri"))
	if err != nil || !middleware.ValidRedirectURI(proxyRedirectURL.String(), p.ProxyRootDomains) {
		httputil.ErrorResponse(w, r, "Invalid redirect parameter", http.StatusBadRequest)
		return
	}

	// get the signature and timestamp values then compare hmac
	proxyRedirectSig := authRedirectURL.Query().Get("sig")
	ts := authRedirectURL.Query().Get("ts")
	if !middleware.ValidSignature(proxyRedirectURL.String(), proxyRedirectSig, ts, p.SharedKey) {
		httputil.ErrorResponse(w, r, "Invalid redirect parameter", http.StatusBadRequest)
		return
	}

	// concat base64'd nonce and authenticate url to make state
	state := base64.URLEncoding.EncodeToString([]byte(fmt.Sprintf("%v:%v", nonce, authRedirectURL.String())))
	// build the provider sign in url
	signInURL := p.provider.GetSignInURL(state)

	http.Redirect(w, r, signInURL, http.StatusFound)
}

// getOAuthCallback completes the oauth cycle from an identity provider's callback
func (p *Authenticate) getOAuthCallback(w http.ResponseWriter, r *http.Request) (string, error) {
	err := r.ParseForm()
	if err != nil {
		log.FromRequest(r).Error().Err(err).Msg("authenticate: bad form on oauth callback")
		return "", httputil.HTTPError{Code: http.StatusInternalServerError, Message: err.Error()}
	}
	errorString := r.Form.Get("error")
	if errorString != "" {
		log.FromRequest(r).Error().Err(err).Msg("authenticate: provider returned error")
		return "", httputil.HTTPError{Code: http.StatusForbidden, Message: errorString}
	}
	code := r.Form.Get("code")
	if code == "" {
		log.FromRequest(r).Error().Err(err).Msg("authenticate: provider missing code")
		return "", httputil.HTTPError{Code: http.StatusBadRequest, Message: "Missing Code"}
	}

	session, err := p.provider.Authenticate(code)
	if err != nil {
		log.FromRequest(r).Error().Err(err).Msg("authenticate: error redeeming authenticate code")
		return "", httputil.HTTPError{Code: http.StatusInternalServerError, Message: err.Error()}
	}

	bytes, err := base64.URLEncoding.DecodeString(r.Form.Get("state"))
	if err != nil {
		log.FromRequest(r).Error().Err(err).Msg("authenticate: failed decoding state")
		return "", httputil.HTTPError{Code: http.StatusBadRequest, Message: "Couldn't decode state"}
	}
	s := strings.SplitN(string(bytes), ":", 2)
	if len(s) != 2 {
		return "", httputil.HTTPError{Code: http.StatusBadRequest, Message: "Invalid State"}
	}
	nonce := s[0]
	redirect := s[1]
	c, err := p.csrfStore.GetCSRF(r)
	if err != nil {
		log.FromRequest(r).Error().Err(err).Msg("authenticate: bad csrf")
		return "", httputil.HTTPError{Code: http.StatusForbidden, Message: "Missing CSRF token"}
	}
	p.csrfStore.ClearCSRF(w, r)
	if c.Value != nonce {
		log.FromRequest(r).Error().Err(err).Msg("authenticate: csrf mismatch")
		return "", httputil.HTTPError{Code: http.StatusForbidden, Message: "CSRF failed"}
	}

	if !middleware.ValidRedirectURI(redirect, p.ProxyRootDomains) {
		return "", httputil.HTTPError{Code: http.StatusForbidden, Message: "Invalid Redirect URI"}
	}

	// Set cookie, or deny: validates the session email and group
	if !p.Validator(session.Email) {
		log.FromRequest(r).Error().Err(err).Str("email", session.Email).Msg("invalid email permissions denied")
		return "", httputil.HTTPError{Code: http.StatusForbidden, Message: "You don't have access"}
	}
	err = p.sessionStore.SaveSession(w, r, session)
	if err != nil {
		log.Error().Err(err).Msg("internal error")
		return "", httputil.HTTPError{Code: http.StatusInternalServerError, Message: "Internal Error"}
	}
	return redirect, nil
}

// OAuthCallback handles the callback from the identity provider. Displays an error page if there
// was an error. If successful, redirects back to the proxy-service via the redirect-url.
func (p *Authenticate) OAuthCallback(w http.ResponseWriter, r *http.Request) {
	redirect, err := p.getOAuthCallback(w, r)
	switch h := err.(type) {
	case nil:
		break
	case httputil.HTTPError:
		log.Error().Err(err).Msg("authenticate: oauth callback error")
		httputil.ErrorResponse(w, r, h.Message, h.Code)
		return
	default:
		log.Error().Err(err).Msg("authenticate: unexpected oauth callback error")
		httputil.ErrorResponse(w, r, "Internal Error", http.StatusInternalServerError)
		return
	}
	// redirect back to the proxy-service
	http.Redirect(w, r, redirect, http.StatusFound)
}
