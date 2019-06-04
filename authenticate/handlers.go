package authenticate // import "github.com/pomerium/pomerium/authenticate"

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/pomerium/pomerium/internal/cryptutil"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/middleware"
	"github.com/pomerium/pomerium/internal/sessions"
)

// CSPHeaders are the content security headers added to the service's handlers
var CSPHeaders = map[string]string{
	"Content-Security-Policy": "default-src 'none'; style-src 'self'" +
		" 'sha256-z9MsgkMbQjRSLxzAfN55jB3a9pP0PQ4OHFH8b4iDP6s=' " +
		" 'sha256-qnVkQSG7pWu17hBhIw0kCpfEB3XGvt0mNRa6+uM6OUU=' " +
		" 'sha256-qOdRsNZhtR+htazbcy7guQl3Cn1cqOw1FcE4d3llae0='; " +
		"img-src 'self';",
	"Referrer-Policy": "Same-origin",
}

// Handler returns the authenticate service's HTTP request multiplexer, and routes.
func (a *Authenticate) Handler() http.Handler {
	// validation middleware chain
	c := middleware.NewChain()
	c = c.Append(middleware.SetHeaders(CSPHeaders))
	validate := c.Append(middleware.ValidateSignature(a.SharedKey))
	validate = validate.Append(middleware.ValidateRedirectURI(a.RedirectURL))
	mux := http.NewServeMux()
	mux.Handle("/robots.txt", c.ThenFunc(a.RobotsTxt))
	// Identity Provider (IdP) callback endpoints and callbacks
	mux.Handle("/start", c.ThenFunc(a.OAuthStart))
	mux.Handle("/oauth2/callback", c.ThenFunc(a.OAuthCallback))
	// authenticate-server endpoints
	mux.Handle("/sign_in", validate.ThenFunc(a.SignIn))
	mux.Handle("/sign_out", validate.ThenFunc(a.SignOut)) // POST
	return mux
}

// RobotsTxt handles the /robots.txt route.
func (a *Authenticate) RobotsTxt(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "User-agent: *\nDisallow: /")
}

func (a *Authenticate) authenticate(w http.ResponseWriter, r *http.Request, session *sessions.SessionState) error {
	if session.RefreshPeriodExpired() {
		session, err := a.provider.Refresh(r.Context(), session)
		if err != nil {
			return fmt.Errorf("authenticate: session refresh failed : %v", err)
		}
		err = a.sessionStore.SaveSession(w, r, session)
		if err != nil {
			return fmt.Errorf("authenticate: failed saving refreshed session : %v", err)
		}
	} else {
		valid, err := a.provider.Validate(r.Context(), session.IDToken)
		if err != nil || !valid {
			return fmt.Errorf("authenticate: session valid: %v : %v", valid, err)
		}
	}
	return nil
}

// SignIn handles the sign_in endpoint. It attempts to authenticate the user,
// and if the user is not authenticated, it renders a sign in page.
func (a *Authenticate) SignIn(w http.ResponseWriter, r *http.Request) {
	session, err := a.sessionStore.LoadSession(r)
	if err != nil {
		switch err {
		case http.ErrNoCookie, sessions.ErrLifetimeExpired, sessions.ErrInvalidSession:
			log.FromRequest(r).Debug().Err(err).Msg("proxy: invalid session")
			a.sessionStore.ClearSession(w, r)
			a.OAuthStart(w, r)
			return
		default:
			log.FromRequest(r).Error().Err(err).Msg("proxy: unexpected error")
			httpErr := &httputil.Error{Message: "An unexpected error occurred", Code: http.StatusInternalServerError}
			httputil.ErrorResponse(w, r, httpErr)
			return
		}
	}
	err = a.authenticate(w, r, session)
	if err != nil {
		httpErr := &httputil.Error{Message: err.Error(), Code: http.StatusInternalServerError}
		httputil.ErrorResponse(w, r, httpErr)
		return
	}
	if err = r.ParseForm(); err != nil {
		httpErr := &httputil.Error{Message: err.Error(), Code: http.StatusInternalServerError}
		httputil.ErrorResponse(w, r, httpErr)
		return
	}
	// original `state` parameter received from the proxy application.
	state := r.Form.Get("state")
	if state == "" {
		httpErr := &httputil.Error{Message: "no state parameter supplied", Code: http.StatusBadRequest}
		httputil.ErrorResponse(w, r, httpErr)
		return
	}

	redirectURL, err := url.Parse(r.Form.Get("redirect_uri"))
	if err != nil {
		httpErr := &httputil.Error{Message: "malformed redirect_uri parameter passed", Code: http.StatusBadRequest}
		httputil.ErrorResponse(w, r, httpErr)
		return
	}
	// encrypt session state as json blob
	encrypted, err := sessions.MarshalSession(session, a.cipher)
	if err != nil {
		httpErr := &httputil.Error{Message: err.Error(), Code: http.StatusInternalServerError}
		httputil.ErrorResponse(w, r, httpErr)
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

// SignOut signs the user out by trying to revoke the user's remote identity session along with
// the associated local session state. Handles both GET and POST.
func (a *Authenticate) SignOut(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		log.Error().Err(err).Msg("authenticate: error SignOut form")
		httpErr := &httputil.Error{Code: http.StatusInternalServerError}
		httputil.ErrorResponse(w, r, httpErr)
		return
	}
	redirectURI := r.Form.Get("redirect_uri")
	session, err := a.sessionStore.LoadSession(r)
	if err != nil {
		log.Error().Err(err).Msg("authenticate: no session to signout, redirect and clear")
		http.Redirect(w, r, redirectURI, http.StatusFound)
		return
	}
	a.sessionStore.ClearSession(w, r)
	err = a.provider.Revoke(session.AccessToken)
	if err != nil {
		log.Error().Err(err).Msg("authenticate: failed to revoke user session")
		httpErr := &httputil.Error{Message: fmt.Sprintf("could not revoke session: %s ", err.Error()), Code: http.StatusBadRequest}
		httputil.ErrorResponse(w, r, httpErr)
		return
	}
	http.Redirect(w, r, redirectURI, http.StatusFound)
}

// OAuthStart starts the authenticate process by redirecting to the identity provider.
// https://tools.ietf.org/html/rfc6749#section-4.2.1
func (a *Authenticate) OAuthStart(w http.ResponseWriter, r *http.Request) {
	authRedirectURL := a.RedirectURL.ResolveReference(r.URL)

	// generate a nonce to check following authentication with the IdP
	nonce := fmt.Sprintf("%x", cryptutil.GenerateKey())
	a.csrfStore.SetCSRF(w, r, nonce)

	// verify redirect uri is from the root domain
	if !middleware.SameDomain(authRedirectURL, a.RedirectURL) {
		httpErr := &httputil.Error{Message: "Invalid redirect parameter: redirect uri not from the root domain", Code: http.StatusBadRequest}
		httputil.ErrorResponse(w, r, httpErr)
		return
	}

	// verify proxy url is from the root domain
	proxyRedirectURL, err := url.Parse(authRedirectURL.Query().Get("redirect_uri"))
	if err != nil || !middleware.SameDomain(proxyRedirectURL, a.RedirectURL) {
		httpErr := &httputil.Error{Message: "Invalid redirect parameter: proxy url not from the root domain", Code: http.StatusBadRequest}
		httputil.ErrorResponse(w, r, httpErr)
		return
	}

	// get the signature and timestamp values then compare hmac
	proxyRedirectSig := authRedirectURL.Query().Get("sig")
	ts := authRedirectURL.Query().Get("ts")
	if !middleware.ValidSignature(proxyRedirectURL.String(), proxyRedirectSig, ts, a.SharedKey) {
		httpErr := &httputil.Error{Message: "Invalid redirect parameter: invalid signature", Code: http.StatusBadRequest}
		httputil.ErrorResponse(w, r, httpErr)
		return
	}

	// concat base64'd nonce and authenticate url to make state
	state := base64.URLEncoding.EncodeToString([]byte(fmt.Sprintf("%v:%v", nonce, authRedirectURL.String())))

	// build the provider sign in url
	signInURL := a.provider.GetSignInURL(state)
	http.Redirect(w, r, signInURL, http.StatusFound)
}

// OAuthCallback handles the callback from the identity provider. Displays an error page if there
// was an error. If successful, the user is redirected back to the proxy-service.
func (a *Authenticate) OAuthCallback(w http.ResponseWriter, r *http.Request) {
	redirect, err := a.getOAuthCallback(w, r)
	switch h := err.(type) {
	case nil:
		break
	case httputil.Error:
		log.Error().Err(err).Msg("authenticate: oauth callback error")
		httpErr := &httputil.Error{Message: h.Message, Code: h.Code}
		httputil.ErrorResponse(w, r, httpErr)
		return
	default:
		log.Error().Err(err).Msg("authenticate: unexpected oauth callback error")
		httpErr := &httputil.Error{Message: "Internal Error", Code: http.StatusInternalServerError}
		httputil.ErrorResponse(w, r, httpErr)
		return
	}
	// redirect back to the proxy-service via sign_in
	http.Redirect(w, r, redirect, http.StatusFound)
}

// getOAuthCallback completes the oauth cycle from an identity provider's callback
func (a *Authenticate) getOAuthCallback(w http.ResponseWriter, r *http.Request) (string, error) {
	// handle the callback response from the identity provider
	if err := r.ParseForm(); err != nil {
		return "", httputil.Error{Code: http.StatusInternalServerError, Message: err.Error()}
	}
	errorString := r.Form.Get("error")
	if errorString != "" {
		log.FromRequest(r).Error().Str("Error", errorString).Msg("authenticate: provider returned error")
		return "", httputil.Error{Code: http.StatusForbidden, Message: errorString}
	}
	code := r.Form.Get("code")
	if code == "" {
		log.FromRequest(r).Error().Msg("authenticate: provider missing code")
		return "", httputil.Error{Code: http.StatusBadRequest, Message: "Missing Code"}

	}

	// validate the returned code with the identity provider
	session, err := a.provider.Authenticate(code)
	if err != nil {
		log.FromRequest(r).Error().Err(err).Msg("authenticate: error redeeming authenticate code")
		return "", httputil.Error{Code: http.StatusInternalServerError, Message: err.Error()}
	}

	// okay, time to go back to the proxy service.
	bytes, err := base64.URLEncoding.DecodeString(r.Form.Get("state"))
	if err != nil {
		log.FromRequest(r).Error().Err(err).Msg("authenticate: failed decoding state")
		return "", httputil.Error{Code: http.StatusBadRequest, Message: "Couldn't decode state"}
	}
	s := strings.SplitN(string(bytes), ":", 2)
	if len(s) != 2 {
		return "", httputil.Error{Code: http.StatusBadRequest, Message: "Invalid State"}
	}
	nonce := s[0]
	redirect := s[1]
	c, err := a.csrfStore.GetCSRF(r)
	defer a.csrfStore.ClearCSRF(w, r)
	if err != nil || c.Value != nonce {
		log.FromRequest(r).Error().Err(err).Msg("authenticate: csrf failure")
		return "", httputil.Error{Code: http.StatusForbidden, Message: "CSRF failed"}
	}
	redirectURL, err := url.Parse(redirect)
	if err != nil {
		log.FromRequest(r).Error().Err(err).Msg("authenticate: malformed redirect url")
		return "", httputil.Error{Code: http.StatusForbidden, Message: "Malformed redirect url"}
	}
	// sanity check, we are redirecting back to the same subdomain right?
	if !middleware.SameDomain(redirectURL, a.RedirectURL) {
		return "", httputil.Error{Code: http.StatusBadRequest, Message: "Invalid Redirect URI domain"}
	}

	err = a.sessionStore.SaveSession(w, r, session)
	if err != nil {
		log.Error().Err(err).Msg("authenticate: failed saving new session")
		return "", httputil.Error{Code: http.StatusInternalServerError, Message: "Internal Error"}
	}

	return redirect, nil
}
