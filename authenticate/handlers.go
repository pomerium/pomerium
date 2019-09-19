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

	"github.com/pomerium/csrf"

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
	r := httputil.NewRouter()
	r.Use(middleware.SetHeaders(CSPHeaders))
	r.Use(csrf.Protect(
		a.cookieSecret,
		csrf.Path("/"),
		csrf.Domain(a.cookieDomain),
		csrf.UnsafePaths([]string{callbackPath}), // enforce CSRF on "safe" handler
		csrf.FormValueName("state"),              // rfc6749 section-10.12
		csrf.CookieName(fmt.Sprintf("%s_csrf", a.cookieName)),
		csrf.ErrorHandler(http.HandlerFunc(httputil.CSRFFailureHandler)),
	))

	r.HandleFunc("/robots.txt", a.RobotsTxt).Methods(http.MethodGet)
	// Identity Provider (IdP) endpoints
	r.HandleFunc("/oauth2/callback", a.OAuthCallback).Methods(http.MethodGet)
	r.HandleFunc("/api/v1/token", a.ExchangeToken)

	// Proxy service endpoints
	v := r.PathPrefix("/.pomerium").Subrouter()
	v.Use(middleware.ValidateSignature(a.SharedKey))
	v.Use(middleware.ValidateRedirectURI(a.RedirectURL))
	v.Use(sessions.RetrieveSession(a.sessionStore))
	v.Use(a.VerifySession)

	v.HandleFunc("/sign_in", a.SignIn)
	v.HandleFunc("/sign_out", a.SignOut)
	return r
}

// VerifySession is the middleware used to enforce a valid authentication
// session state is attached to the users's request context.
func (a *Authenticate) VerifySession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		state, err := sessions.FromContext(r.Context())
		if errors.Is(err, sessions.ErrExpired) {
			if err := a.refresh(w, r, state); err != nil {
				log.FromRequest(r).Debug().Str("cause", err.Error()).Msg("authenticate: couldn't refresh session")
				a.sessionStore.ClearSession(w, r)
				a.redirectToIdentityProvider(w, r)
				return
			}

		} else if err != nil {
			log.FromRequest(r).Err(err).Msg("authenticate: unexpected session state")
			a.sessionStore.ClearSession(w, r)
			a.redirectToIdentityProvider(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (a *Authenticate) refresh(w http.ResponseWriter, r *http.Request, s *sessions.State) error {
	newSession, err := a.provider.Refresh(r.Context(), s)
	if err != nil {
		return fmt.Errorf("authenticate: refresh failed: %w", err)
	}
	if err := a.sessionStore.SaveSession(w, r, newSession); err != nil {
		return fmt.Errorf("authenticate: refresh save failed: %w", err)
	}
	return nil

}

// RobotsTxt handles the /robots.txt route.
func (a *Authenticate) RobotsTxt(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "User-agent: *\nDisallow: /")
}

// SignIn handles to authenticating a user.
func (a *Authenticate) SignIn(w http.ResponseWriter, r *http.Request) {
	redirectURL, err := urlutil.ParseAndValidateURL(r.FormValue("redirect_uri"))
	if err != nil {
		httputil.ErrorResponse(w, r, httputil.Error("malformed redirect_uri", http.StatusBadRequest, err))
		return
	}
	http.Redirect(w, r, redirectURL.String(), http.StatusFound)
}

// SignOut signs the user out and attempts to revoke the user's identity session
// Handles both GET and POST.
func (a *Authenticate) SignOut(w http.ResponseWriter, r *http.Request) {
	session, err := sessions.FromContext(r.Context())
	if err != nil {
		httputil.ErrorResponse(w, r, httputil.Error("", http.StatusBadRequest, err))
		return
	}
	a.sessionStore.ClearSession(w, r)
	err = a.provider.Revoke(session.AccessToken)
	if err != nil {
		httputil.ErrorResponse(w, r, httputil.Error("could not revoke user session", http.StatusBadRequest, err))
		return
	}
	redirectURL, err := urlutil.ParseAndValidateURL(r.FormValue("redirect_uri"))
	if err != nil {
		httputil.ErrorResponse(w, r, httputil.Error("malformed redirect_uri", http.StatusBadRequest, err))
		return
	}
	http.Redirect(w, r, redirectURL.String(), http.StatusFound)
}

// redirectToIdentityProvider starts the authenticate process by redirecting the
// user to their respective identity provider. This function also builds the
// 'state' parameter which is encrypted and includes authenticating data
// for validation.
// 'state' is : nonce|timestamp|redirect_url|encrypt(redirect_url)+mac(nonce,ts))

// https://openid.net/specs/openid-connect-core-1_0-final.html#AuthRequest
// https://tools.ietf.org/html/rfc6749#section-4.2.1
func (a *Authenticate) redirectToIdentityProvider(w http.ResponseWriter, r *http.Request) {
	redirectURL := a.RedirectURL.ResolveReference(r.URL)
	nonce := csrf.Token(r)
	now := time.Now().Unix()
	b := []byte(fmt.Sprintf("%s|%d|", nonce, now))
	enc := cryptutil.Encrypt(a.cipher, []byte(redirectURL.String()), b)
	b = append(b, enc...)
	encodedState := base64.URLEncoding.EncodeToString(b)
	http.Redirect(w, r, a.provider.GetSignInURL(encodedState), http.StatusFound)
}

// OAuthCallback handles the callback from the identity provider.
//
// https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowSteps
// https://openid.net/specs/openid-connect-core-1_0.html#AuthResponse
func (a *Authenticate) OAuthCallback(w http.ResponseWriter, r *http.Request) {
	redirect, err := a.getOAuthCallback(w, r)
	if err != nil {
		httputil.ErrorResponse(w, r, fmt.Errorf("oauth callback : %w", err))
		return
	}
	http.Redirect(w, r, redirect.String(), http.StatusFound)
}

func (a *Authenticate) getOAuthCallback(w http.ResponseWriter, r *http.Request) (*url.URL, error) {
	// Error Authentication Response: rfc6749#section-4.1.2.1 & OIDC#3.1.2.6
	//
	// first, check if the identity provider returned an error
	if idpError := r.FormValue("error"); idpError != "" {
		return nil, httputil.Error(idpError, http.StatusBadRequest, fmt.Errorf("identity provider: %v", idpError))
	}
	// fail if no session redemption code is returned
	code := r.FormValue("code")
	if code == "" {
		return nil, httputil.Error("identity provider returned empty code", http.StatusBadRequest, nil)
	}

	// Successful Authentication Response: rfc6749#section-4.1.2 & OIDC#3.1.2.5
	//
	// Exchange the supplied Authorization Code for a valid user session.
	session, err := a.provider.Authenticate(r.Context(), code)
	if err != nil {
		return nil, fmt.Errorf("error redeeming authenticate code: %w", err)
	}
	// state includes a csrf nonce (validated by middleware) and redirect uri
	bytes, err := base64.URLEncoding.DecodeString(r.FormValue("state"))
	if err != nil {
		return nil, httputil.Error("malformed state", http.StatusBadRequest, err)
	}

	// split state into its it's components, e.g.
	// (nonce|timestamp|redirect_url|encrypted_data(redirect_url)+mac(nonce,ts))
	statePayload := strings.SplitN(string(bytes), "|", 3)
	if len(statePayload) != 3 {
		return nil, httputil.Error("'state' is malformed", http.StatusBadRequest,
			fmt.Errorf("state malformed, size: %d", len(statePayload)))
	}

	// verify that the returned timestamp is valid (replay attack)
	if err := cryptutil.ValidTimestamp(statePayload[1]); err != nil {
		return nil, httputil.Error(err.Error(), http.StatusBadRequest, err)
	}

	// Use our AEAD construct to enforce secrecy and authenticity,:
	// mac: to validate the nonce again, and above timestamp
	// decrypt: to prevent leaking 'redirect_uri' to IdP or logs)
	b := []byte(fmt.Sprint(statePayload[0], "|", statePayload[1], "|"))
	redirectString, err := cryptutil.Decrypt(a.cipher, []byte(statePayload[2]), b)
	if err != nil {
		return nil, httputil.Error("'state' has invalid hmac", http.StatusBadRequest, err)
	}

	redirectURL, err := urlutil.ParseAndValidateURL(string(redirectString))
	if err != nil {
		return nil, httputil.Error("'state' has invalid redirect uri", http.StatusBadRequest, err)
	}

	// OK. Looks good so let's persist our user session
	if err := a.sessionStore.SaveSession(w, r, session); err != nil {
		return nil, fmt.Errorf("failed saving new session: %w", err)
	}
	return redirectURL, nil
}

// ExchangeToken takes an identity provider issued JWT as input ('id_token)
// and exchanges that token for a pomerium session. The provided token's
// audience ('aud') attribute must match Pomerium's client_id.
func (a *Authenticate) ExchangeToken(w http.ResponseWriter, r *http.Request) {
	code := r.FormValue("id_token")
	if code == "" {
		httputil.ErrorResponse(w, r, httputil.Error("missing id token", http.StatusBadRequest, nil))
		return
	}
	session, err := a.provider.IDTokenToSession(r.Context(), code)
	if err != nil {
		httputil.ErrorResponse(w, r, err)
		return
	}
	encToken, err := sessions.MarshalSession(session, a.encoder)
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
