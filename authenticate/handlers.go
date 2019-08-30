package authenticate // import "github.com/pomerium/pomerium/authenticate"

import (
	"encoding/base64"
	"encoding/json"
	"errors"
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
	"github.com/pomerium/pomerium/internal/urlutil"
)

// CSPHeaders are the content security headers added to the service's handlers
// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/script-src
var CSPHeaders = map[string]string{
	"Content-Security-Policy": "default-src 'none'; style-src 'self'" +
		" 'sha256-z9MsgkMbQjRSLxzAfN55jB3a9pP0PQ4OHFH8b4iDP6s=' " +
		" 'sha256-qnVkQSG7pWu17hBhIw0kCpfEB3XGvt0mNRa6+uM6OUU=' " +
		" 'sha256-qOdRsNZhtR+htazbcy7guQl3Cn1cqOw1FcE4d3llae0='; " +
		"img-src 'self';",
	"Referrer-Policy": "Same-origin",
}

// Handler returns the authenticate service's HTTP multiplexer, and routes.
func (a *Authenticate) Handler() http.Handler {
	// validation middleware chain
	c := middleware.NewChain()
	c = c.Append(middleware.SetHeaders(CSPHeaders))
	mux := http.NewServeMux()
	mux.Handle("/robots.txt", c.ThenFunc(a.RobotsTxt))
	// Identity Provider (IdP) endpoints
	mux.Handle("/oauth2", c.ThenFunc(a.OAuthStart))
	mux.Handle("/oauth2/callback", c.ThenFunc(a.OAuthCallback))
	// Proxy service endpoints
	validationMiddlewares := c.Append(
		middleware.ValidateSignature(a.SharedKey),
		middleware.ValidateRedirectURI(a.RedirectURL),
	)
	mux.Handle("/sign_in", validationMiddlewares.ThenFunc(a.SignIn))
	mux.Handle("/sign_out", validationMiddlewares.ThenFunc(a.SignOut)) // POST
	// Direct user access endpoints
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

func (a *Authenticate) loadExisting(w http.ResponseWriter, r *http.Request) (*sessions.State, error) {
	session, err := a.sessionStore.LoadSession(r)
	if err != nil {
		return nil, err
	}
	err = session.Valid()
	if err == nil {
		return session, nil
	} else if !errors.Is(err, sessions.ErrExpired) {
		return nil, fmt.Errorf("authenticate: non-refreshable error: %w", err)
	} else {
		return a.refresh(w, r, session)
	}
}

func (a *Authenticate) refresh(w http.ResponseWriter, r *http.Request, s *sessions.State) (*sessions.State, error) {
	newSession, err := a.provider.Refresh(r.Context(), s)
	if err != nil {
		return nil, fmt.Errorf("authenticate: refresh failed: %w", err)
	}
	if err := a.sessionStore.SaveSession(w, r, newSession); err != nil {
		return nil, fmt.Errorf("authenticate: refresh save failed: %w", err)
	}
	return newSession, nil

}

// SignIn handles to authenticating a user.
func (a *Authenticate) SignIn(w http.ResponseWriter, r *http.Request) {
	session, err := a.loadExisting(w, r)
	if err != nil {
		log.FromRequest(r).Debug().Err(err).Msg("authenticate: need new session")
		a.sessionStore.ClearSession(w, r)
		a.OAuthStart(w, r)
		return
	}
	if err := r.ParseForm(); err != nil {
		httputil.ErrorResponse(w, r, err)
		return
	}
	state := r.Form.Get("state")
	if state == "" {
		httputil.ErrorResponse(w, r, httputil.Error("sign in state empty", http.StatusBadRequest, nil))
		return
	}

	redirectURL, err := urlutil.ParseAndValidateURL(r.Form.Get("redirect_uri"))
	if err != nil {
		httputil.ErrorResponse(w, r, httputil.Error("malformed redirect_uri", http.StatusBadRequest, err))
		return
	}
	// encrypt session state as json blob
	encrypted, err := sessions.MarshalSession(session, a.cipher)
	if err != nil {
		httputil.ErrorResponse(w, r, httputil.Error("couldn't marshal session", http.StatusInternalServerError, err))
		return
	}
	http.Redirect(w, r, getAuthCodeRedirectURL(redirectURL, state, encrypted), http.StatusFound)
}

func getAuthCodeRedirectURL(redirectURL *url.URL, state, authCode string) string {
	// ParseQuery err handled by go's mux stack
	params, _ := url.ParseQuery(redirectURL.RawQuery)
	params.Set("code", authCode)
	params.Set("state", state)
	redirectURL.RawQuery = params.Encode()
	return redirectURL.String()
}

// SignOut signs the user out and attempts to revoke the user's identity session
// Handles both GET and POST.
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
		httputil.ErrorResponse(w, r, httputil.Error("could not revoke user session", http.StatusBadRequest, err))
		return
	}
	http.Redirect(w, r, redirectURI, http.StatusFound)
}

// OAuthStart starts the authenticate process by redirecting to the identity provider.
// https://openid.net/specs/openid-connect-core-1_0-final.html#AuthRequest
// https://tools.ietf.org/html/rfc6749#section-4.2.1
func (a *Authenticate) OAuthStart(w http.ResponseWriter, r *http.Request) {
	authRedirectURL := a.RedirectURL.ResolveReference(r.URL)

	// Nonce is the opaque, cryptographically binding value used to maintain
	// state between the request and the callback.
	// OIDC : 3.1.2.1.  Authentication Request
	nonce := fmt.Sprintf("%x", cryptutil.GenerateKey())
	a.csrfStore.SetCSRF(w, r, nonce)
	// Redirection URI to which the response will be sent. This URI MUST exactly
	// match one of the Redirection URI values for the Client pre-registered at
	// at your identity provider
	proxyRedirectURL, err := urlutil.ParseAndValidateURL(authRedirectURL.Query().Get("redirect_uri"))
	if err != nil || !middleware.SameDomain(proxyRedirectURL, a.RedirectURL) {
		httputil.ErrorResponse(w, r, httputil.Error("proxy url not from the root domain", http.StatusBadRequest, err))
		return
	}

	// get the signature and timestamp values then compare hmac
	proxyRedirectSig := authRedirectURL.Query().Get("sig")
	ts := authRedirectURL.Query().Get("ts")
	if !middleware.ValidSignature(proxyRedirectURL.String(), proxyRedirectSig, ts, a.SharedKey) {
		httputil.ErrorResponse(w, r, httputil.Error("invalid signature", http.StatusBadRequest, nil))
		return
	}
	// State is the opaque value used to maintain state between the request and
	// the callback; contains both the nonce and redirect URI
	state := base64.URLEncoding.EncodeToString([]byte(fmt.Sprintf("%v:%v", nonce, authRedirectURL.String())))

	// build the provider sign in url
	signInURL := a.provider.GetSignInURL(state)
	http.Redirect(w, r, signInURL, http.StatusFound)
}

// OAuthCallback handles the callback from the identity provider.
// https://openid.net/specs/openid-connect-core-1_0.html#AuthResponse
func (a *Authenticate) OAuthCallback(w http.ResponseWriter, r *http.Request) {
	redirect, err := a.getOAuthCallback(w, r)
	if err != nil {
		httputil.ErrorResponse(w, r, fmt.Errorf("oauth callback : %w", err))
		return
	}
	// redirect back to the proxy-service via sign_in
	http.Redirect(w, r, redirect.String(), http.StatusFound)
}

func (a *Authenticate) getOAuthCallback(w http.ResponseWriter, r *http.Request) (*url.URL, error) {
	if err := r.ParseForm(); err != nil {
		return nil, httputil.Error("invalid signature", http.StatusBadRequest, err)
	}
	// OIDC : 3.1.2.6.  Authentication Error Response
	// https://openid.net/specs/openid-connect-core-1_0-final.html#AuthError
	if idpError := r.Form.Get("error"); idpError != "" {
		return nil, httputil.Error("provider returned an error", http.StatusBadRequest, fmt.Errorf("provider error: %v", idpError))
	}
	code := r.Form.Get("code")
	if code == "" {
		return nil, httputil.Error("provider didn't reply with code", http.StatusBadRequest, nil)
	}

	// validate the returned code with the identity provider
	session, err := a.provider.Authenticate(r.Context(), code)
	if err != nil {
		return nil, fmt.Errorf("error redeeming authenticate code: %w", err)
	}

	// OIDC : 3.1.2.5.  Successful Authentication Response
	// Opaque value used to maintain state between the request and the callback.
	bytes, err := base64.URLEncoding.DecodeString(r.Form.Get("state"))
	if err != nil {
		return nil, fmt.Errorf("failed decoding state: %w", err)
	}
	s := strings.SplitN(string(bytes), ":", 2)
	if len(s) != 2 {
		return nil, fmt.Errorf("invalid state size: %d", len(s))
	}
	// state contains the csrf nonce and redirect uri
	nonce := s[0]
	redirect := s[1]
	c, err := a.csrfStore.GetCSRF(r)
	defer a.csrfStore.ClearCSRF(w, r)
	if err != nil || c.Value != nonce {
		return nil, fmt.Errorf("csrf failure: %w", err)
	}
	redirectURL, err := urlutil.ParseAndValidateURL(redirect)
	if err != nil {
		return nil, httputil.Error(fmt.Sprintf("invalid redirect uri %s", redirect), http.StatusBadRequest, err)
	}
	// sanity check, we are redirecting back to the same subdomain right?
	if !middleware.SameDomain(redirectURL, a.RedirectURL) {
		return nil, httputil.Error(fmt.Sprintf("invalid redirect domain %v, %v", redirectURL, a.RedirectURL), http.StatusBadRequest, nil)
	}

	if err := a.sessionStore.SaveSession(w, r, session); err != nil {
		return nil, fmt.Errorf("failed saving new session: %w", err)
	}
	return redirectURL, nil
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
		httputil.ErrorResponse(w, r, httputil.Error("missing id token", http.StatusBadRequest, nil))
		return
	}
	session, err := a.provider.IDTokenToSession(r.Context(), code)
	if err != nil {
		httputil.ErrorResponse(w, r, err)
		return
	}
	encToken, err := sessions.MarshalSession(session, a.cipher)
	if err != nil {
		httputil.ErrorResponse(w, r, httputil.Error(err.Error(), http.StatusBadRequest, err))
		return
	}
	restSession := struct {
		Token  string
		Expiry time.Time `json:",omitempty"`
	}{
		Token:  encToken,
		Expiry: session.RefreshDeadline,
	}

	jsonBytes, err := json.Marshal(restSession)
	if err != nil {
		httputil.ErrorResponse(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonBytes)
}
