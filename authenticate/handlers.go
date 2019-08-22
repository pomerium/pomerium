package authenticate // import "github.com/pomerium/pomerium/authenticate"

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/xerrors"

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
	// programmatic authentication endpoints
	mux.Handle("/api/v1/token", c.ThenFunc(a.ExchangeToken))
	return mux
}

// RobotsTxt handles the /robots.txt route.
func (a *Authenticate) RobotsTxt(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "User-agent: *\nDisallow: /")
}

func (a *Authenticate) authenticate(w http.ResponseWriter, r *http.Request, session *sessions.SessionState) error {
	if session.RefreshPeriodExpired() {
		session, err := a.provider.Refresh(r.Context(), session)
		if err != nil {
			return xerrors.Errorf("session refresh failed : %w", err)
		}
		if err = a.sessionStore.SaveSession(w, r, session); err != nil {
			return xerrors.Errorf("failed saving refreshed session : %w", err)
		}
	} else {
		valid, err := a.provider.Validate(r.Context(), session.IDToken)
		if err != nil || !valid {
			return xerrors.Errorf("session valid: %v : %w", valid, err)
		}
	}
	return nil
}

func (a *Authenticate) SignIn(w http.ResponseWriter, r *http.Request) {
	session, err := a.sessionStore.LoadSession(r)
	if err != nil {
		log.FromRequest(r).Debug().Err(err).Msg("authenticate: invalid session, restart oauth")
		a.sessionStore.ClearSession(w, r)
		a.OAuthStart(w, r)
		return
	}
	if err := a.authenticate(w, r, session); err != nil {
		httputil.ErrorResponse(w, r, err)
		return
	}
	if err := r.ParseForm(); err != nil {
		httputil.ErrorResponse(w, r, err)
		return
	}

	state := r.Form.Get("state") // grab
	if state == "" {
		httputil.ErrorResponse(w, r, httputil.NewHTTPError("sign in state empty", http.StatusBadRequest))
		return
	}

	redirectURL, err := url.Parse(r.Form.Get("redirect_uri"))
	if err != nil {
		httputil.ErrorResponse(w, r, httputil.WrappedHTTPError("malformed redirect_uri parameter passed", http.StatusBadRequest, err))
		return
	}
	// encrypt session state as json blob
	encrypted, err := sessions.MarshalSession(session, a.cipher)
	if err != nil {
		httputil.ErrorResponse(w, r, httputil.WrappedHTTPError("couldn't marshall session", http.StatusInternalServerError, err))
		return
	}
	http.Redirect(w, r, getAuthCodeRedirectURL(redirectURL, state, encrypted), http.StatusFound)
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
		httputil.ErrorResponse(w, r, err)
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
		httputil.ErrorResponse(w, r, httputil.WrappedHTTPError("could not revoke user session", http.StatusBadRequest, err))
		return
	}
	http.Redirect(w, r, redirectURI, http.StatusFound)
}

// OAuthStart starts the authenticate process by redirecting to the identity provider.
// https://tools.ietf.org/html/rfc6749#section-4.2.1
func (a *Authenticate) OAuthStart(w http.ResponseWriter, r *http.Request) {
	authRedirectURL := a.RedirectURL.ResolveReference(r.URL)

	// generate a nonce to which will be checked when the IdP makes its callback
	nonce := fmt.Sprintf("%x", cryptutil.GenerateKey())
	a.csrfStore.SetCSRF(w, r, nonce)

	// verify redirect uri is from the same root domain
	if !middleware.SameDomain(authRedirectURL, a.RedirectURL) {
		httputil.ErrorResponse(w, r, httputil.NewHTTPError("redirect uri not from the root domain", http.StatusBadRequest))
		return
	}

	// verify proxy url is from the same root domain
	proxyRedirectURL, err := url.Parse(authRedirectURL.Query().Get("redirect_uri"))
	if err != nil || !middleware.SameDomain(proxyRedirectURL, a.RedirectURL) {
		httputil.ErrorResponse(w, r, httputil.WrappedHTTPError("proxy url not from the root domain", http.StatusBadRequest, err))
		return
	}

	// get the signature and timestamp values then compare hmac
	proxyRedirectSig := authRedirectURL.Query().Get("sig")
	ts := authRedirectURL.Query().Get("ts")
	if !middleware.ValidSignature(proxyRedirectURL.String(), proxyRedirectSig, ts, a.SharedKey) {
		httputil.ErrorResponse(w, r, httputil.NewHTTPError("invalid signature", http.StatusBadRequest))
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
	if err != nil {
		httputil.ErrorResponse(w, r, xerrors.Errorf("authenticate: oauth callback : %w", err))
		return
	}
	// redirect back to the proxy-service via sign_in
	http.Redirect(w, r, redirect, http.StatusFound)
}

// getOAuthCallback completes the oauth cycle from an identity provider's callback
func (a *Authenticate) getOAuthCallback(w http.ResponseWriter, r *http.Request) (string, error) {
	// handle the callback response from the identity provider
	if err := r.ParseForm(); err != nil {
		return "", err
	}
	if errorString := r.Form.Get("error"); errorString != "" {
		return "", xerrors.Errorf("provider returned error: %v", errorString)
	}
	code := r.Form.Get("code")
	if code == "" {
		return "", xerrors.Errorf("provider missing code")
	}

	// validate the returned code with the identity provider
	session, err := a.provider.Authenticate(r.Context(), code)
	if err != nil {
		return "", xerrors.Errorf("error redeeming authenticate code: %w", err)
	}

	// okay, time to go back to the proxy service.
	bytes, err := base64.URLEncoding.DecodeString(r.Form.Get("state"))
	if err != nil {
		return "", xerrors.Errorf("failed decoding state: %w", err)
	}
	s := strings.SplitN(string(bytes), ":", 2)
	if len(s) != 2 {
		return "", xerrors.Errorf("invalid state size: %v", len(s))
	}
	nonce := s[0]
	redirect := s[1]
	c, err := a.csrfStore.GetCSRF(r)
	defer a.csrfStore.ClearCSRF(w, r)
	if err != nil || c.Value != nonce {
		return "", xerrors.Errorf("csrf failure: %w", err)

	}
	redirectURL, err := url.Parse(redirect)
	if err != nil {
		return "", xerrors.Errorf("malformed redirect url: %w", err)
	}
	// sanity check, we are redirecting back to the same subdomain right?
	if !middleware.SameDomain(redirectURL, a.RedirectURL) {
		return "", xerrors.Errorf("invalid redirect domain %v, %v", redirectURL, a.RedirectURL)
	}

	if err := a.sessionStore.SaveSession(w, r, session); err != nil {
		return "", xerrors.Errorf("failed saving new session: %w", err)
	}
	return redirect, nil
}

// ExchangeToken takes an identity provider issued JWT as input ('id_token)
// and exchanges that token for a pomerium session. The provided token's
// audience ('aud') attribute must match Pomerium's client_id.
func (a *Authenticate) ExchangeToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		httputil.ErrorResponse(w, r, err)
		return
	}
	code := r.Form.Get("id_token")
	if code == "" {
		httputil.ErrorResponse(w, r, httputil.NewHTTPError("provider missing id token", http.StatusBadRequest))
		return
	}
	session, err := a.provider.IDTokenToSession(r.Context(), code)
	if err != nil {
		httputil.ErrorResponse(w, r, httputil.WrappedHTTPError("could not exchange identity for session", http.StatusInternalServerError, err))
		return
	}
	if err := a.restStore.SaveSession(w, r, session); err != nil {
		httputil.ErrorResponse(w, r, httputil.WrappedHTTPError("failed returning new session", http.StatusInternalServerError, err))
		return
	}
}
