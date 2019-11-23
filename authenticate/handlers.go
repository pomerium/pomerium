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

	"github.com/rs/cors"

	"github.com/pomerium/csrf"
	"github.com/pomerium/pomerium/internal/cryptutil"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/middleware"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/internal/urlutil"
)

// Handler returns the authenticate service's handler chain.
func (a *Authenticate) Handler() http.Handler {
	r := httputil.NewRouter()
	r.Use(middleware.SetHeaders(httputil.HeadersContentSecurityPolicy))
	r.Use(csrf.Protect(
		a.cookieSecret,
		csrf.Secure(a.cookieOptions.Secure),
		csrf.Path("/"),
		csrf.UnsafePaths([]string{callbackPath}), // enforce CSRF on "safe" handler
		csrf.FormValueName("state"),              // rfc6749 section-10.12
		csrf.CookieName(fmt.Sprintf("%s_csrf", a.cookieOptions.Name)),
		csrf.ErrorHandler(http.HandlerFunc(httputil.CSRFFailureHandler)),
	))

	r.HandleFunc("/robots.txt", a.RobotsTxt).Methods(http.MethodGet)
	// Identity Provider (IdP) endpoints
	r.HandleFunc("/oauth2/callback", a.OAuthCallback).Methods(http.MethodGet)

	// Proxy service endpoints
	v := r.PathPrefix("/.pomerium").Subrouter()
	c := cors.New(cors.Options{
		AllowOriginRequestFunc: func(r *http.Request, _ string) bool {
			return middleware.ValidateRedirectURI(r, a.sharedKey)
		},
		AllowCredentials: true,
		AllowedHeaders:   []string{"*"},
	})
	v.Use(c.Handler)
	v.Use(middleware.ValidateSignature(a.sharedKey))
	v.Use(sessions.RetrieveSession(a.sessionLoaders...))
	v.Use(a.VerifySession)
	v.HandleFunc("/sign_in", a.SignIn)
	v.HandleFunc("/sign_out", a.SignOut)

	// programmatic access api endpoint
	api := r.PathPrefix("/api").Subrouter()
	api.Use(sessions.RetrieveSession(a.sessionLoaders...))
	api.HandleFunc("/v1/refresh", a.RefreshAPI)

	return r
}

// VerifySession is the middleware used to enforce a valid authentication
// session state is attached to the users's request context.
func (a *Authenticate) VerifySession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		state, err := sessions.FromContext(r.Context())
		if errors.Is(err, sessions.ErrExpired) {
			if err := a.refresh(w, r, state); err != nil {
				log.FromRequest(r).Info().Err(err).Msg("authenticate: verify session, refresh")
				a.reauthenticateOrFail(w, r, err)
				return
			}
			// redirect to restart middleware-chain following refresh
			httputil.Redirect(w, r, urlutil.GetAbsoluteURL(r).String(), http.StatusFound)
			return
		} else if err != nil {
			log.FromRequest(r).Info().Err(err).Msg("authenticate: verify session")
			a.reauthenticateOrFail(w, r, err)
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
	// grab and parse our redirect_uri
	redirectURL, err := urlutil.ParseAndValidateURL(r.FormValue("redirect_uri"))
	if err != nil {
		httputil.ErrorResponse(w, r, httputil.Error("malformed redirect_uri", http.StatusBadRequest, err))
		return
	}
	// create a clone of the redirect URI, unless this is a programmatic request
	// in which case we will redirect back to proxy's callback endpoint
	callbackURL, _ := urlutil.DeepCopy(redirectURL)

	q := redirectURL.Query()

	if q.Get("pomerium_programmatic_destination_url") != "" {
		callbackURL, err = urlutil.ParseAndValidateURL(q.Get("pomerium_programmatic_destination_url"))
		if err != nil {
			httputil.ErrorResponse(w, r, httputil.Error("", http.StatusBadRequest, err))
			return
		}
	}
	s, err := sessions.FromContext(r.Context())
	if err != nil {
		httputil.ErrorResponse(w, r, httputil.Error("", http.StatusBadRequest, err))
		return
	}
	s.SetImpersonation(q.Get("impersonate_email"), q.Get("impersonate_group"))

	newSession := s.NewSession(a.RedirectURL.Host, []string{a.RedirectURL.Host, callbackURL.Host})
	if q.Get("pomerium_programmatic_destination_url") != "" {
		newSession.Programmatic = true
		encSession, err := a.encryptedEncoder.Marshal(newSession)
		if err != nil {
			httputil.ErrorResponse(w, r, httputil.Error("", http.StatusBadRequest, err))
			return
		}
		q.Set("pomerium_refresh_token", string(encSession))
	}

	// sign the route session, as a JWT
	signedJWT, err := a.sharedEncoder.Marshal(newSession.RouteSession(DefaultSessionDuration))
	if err != nil {
		httputil.ErrorResponse(w, r, httputil.Error("", http.StatusBadRequest, err))
		return
	}
	// encrypt our route-based token JWT avoiding any accidental logging
	encryptedJWT := cryptutil.Encrypt(a.sharedCipher, signedJWT, nil)
	// base64 our encrypted payload for URL-friendlyness
	encodedJWT := base64.URLEncoding.EncodeToString(encryptedJWT)

	// add our encoded and encrypted route-session JWT to a query param
	q.Set("pomerium_jwt", encodedJWT)

	redirectURL.RawQuery = q.Encode()

	callbackURL.Path = "/.pomerium/callback"

	// build our hmac-d redirect URL with our session, pointing back to the
	// proxy's callback URL which is responsible for setting our new route-session
	uri := urlutil.SignedRedirectURL(a.sharedKey, callbackURL, redirectURL)
	httputil.Redirect(w, r, uri.String(), http.StatusFound)
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
	err = a.provider.Revoke(r.Context(), session.AccessToken)
	if err != nil {
		httputil.ErrorResponse(w, r, httputil.Error("could not revoke user session", http.StatusBadRequest, err))
		return
	}
	redirectURL, err := urlutil.ParseAndValidateURL(r.FormValue("redirect_uri"))
	if err != nil {
		httputil.ErrorResponse(w, r, httputil.Error("malformed redirect_uri", http.StatusBadRequest, err))
		return
	}
	httputil.Redirect(w, r, redirectURL.String(), http.StatusFound)
}

// reauthenticateOrFail starts the authenticate process by redirecting the
// user to their respective identity provider. This function also builds the
// 'state' parameter which is encrypted and includes authenticating data
// for validation.
// If the request is a `xhr/ajax` request (e.g the `X-Requested-With` header)
// is set do not redirect but instead return 401 unauthorized.
//
// https://openid.net/specs/openid-connect-core-1_0-final.html#AuthRequest
// https://tools.ietf.org/html/rfc6749#section-4.2.1
// https://developer.mozilla.org/en-US/docs/Web/API/XMLHttpRequest
func (a *Authenticate) reauthenticateOrFail(w http.ResponseWriter, r *http.Request, err error) {
	// If request AJAX/XHR request, return a 401 instead .
	if reqType := r.Header.Get("X-Requested-With"); strings.EqualFold(reqType, "XmlHttpRequest") {
		httputil.ErrorResponse(w, r, httputil.Error(err.Error(), http.StatusUnauthorized, err))
		return
	}
	a.sessionStore.ClearSession(w, r)
	redirectURL := a.RedirectURL.ResolveReference(r.URL)
	nonce := csrf.Token(r)
	now := time.Now().Unix()
	b := []byte(fmt.Sprintf("%s|%d|", nonce, now))
	enc := cryptutil.Encrypt(a.cookieCipher, []byte(redirectURL.String()), b)
	b = append(b, enc...)
	encodedState := base64.URLEncoding.EncodeToString(b)
	httputil.Redirect(w, r, a.provider.GetSignInURL(encodedState), http.StatusFound)
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
	httputil.Redirect(w, r, redirect.String(), http.StatusFound)
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

	// split state into concat'd components
	// (nonce|timestamp|redirect_url|encrypted_data(redirect_url)+mac(nonce,ts))
	statePayload := strings.SplitN(string(bytes), "|", 3)
	if len(statePayload) != 3 {
		return nil, httputil.Error("'state' is malformed", http.StatusBadRequest,
			fmt.Errorf("state malformed, size: %d", len(statePayload)))
	}

	// verify that the returned timestamp is valid
	if err := cryptutil.ValidTimestamp(statePayload[1]); err != nil {
		return nil, httputil.Error(err.Error(), http.StatusBadRequest, err)
	}

	// Use our AEAD construct to enforce secrecy and authenticity:
	// mac: to validate the nonce again, and above timestamp
	// decrypt: to prevent leaking 'redirect_uri' to IdP or logs
	b := []byte(fmt.Sprint(statePayload[0], "|", statePayload[1], "|"))
	redirectString, err := cryptutil.Decrypt(a.cookieCipher, []byte(statePayload[2]), b)
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

// RefreshAPI loads a global state, and attempts to refresh the session's access
// tokens and state with the identity provider. If successful, a new signed JWT
// and refresh token (`refresh_token`) are returned as JSON
func (a *Authenticate) RefreshAPI(w http.ResponseWriter, r *http.Request) {
	s, err := sessions.FromContext(r.Context())
	if err != nil && !errors.Is(err, sessions.ErrExpired) {
		httputil.ErrorResponse(w, r, httputil.Error("", http.StatusBadRequest, err))
		return
	}
	newSession, err := a.provider.Refresh(r.Context(), s)
	if err != nil {
		httputil.ErrorResponse(w, r, httputil.Error("", http.StatusInternalServerError, err))
		return
	}
	newSession = newSession.NewSession(s.Issuer, s.Audience)

	encSession, err := a.encryptedEncoder.Marshal(newSession)
	if err != nil {
		httputil.ErrorResponse(w, r, httputil.Error("", http.StatusInternalServerError, err))
		return
	}

	signedJWT, err := a.sharedEncoder.Marshal(newSession.RouteSession(DefaultSessionDuration))
	if err != nil {
		httputil.ErrorResponse(w, r, httputil.Error("", http.StatusInternalServerError, err))
		return
	}
	var response struct {
		JWT          string `json:"jwt"`
		RefreshToken string `json:"refresh_token"`
	}
	response.RefreshToken = string(encSession)
	response.JWT = string(signedJWT)

	jsonResponse, err := json.Marshal(&response)
	if err != nil {
		httputil.ErrorResponse(w, r, httputil.Error("", http.StatusBadRequest, err))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonResponse)
}
