package authenticate // import "github.com/pomerium/pomerium/authenticate"

import (
	"context"
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
	"github.com/pomerium/pomerium/internal/telemetry/trace"
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
		csrf.UnsafePaths([]string{a.RedirectURL.Path}), // enforce CSRF on "safe" handler
		csrf.FormValueName("state"),                    // rfc6749 section-10.12
		csrf.CookieName(fmt.Sprintf("%s_csrf", a.cookieOptions.Name)),
		csrf.ErrorHandler(httputil.HandlerFunc(httputil.CSRFFailureHandler)),
	))

	r.Path("/robots.txt").HandlerFunc(a.RobotsTxt).Methods(http.MethodGet)
	// Identity Provider (IdP) endpoints
	r.Path("/oauth2/callback").Handler(httputil.HandlerFunc(a.OAuthCallback)).Methods(http.MethodGet)

	// Proxy service endpoints
	v := r.PathPrefix("/.pomerium").Subrouter()
	c := cors.New(cors.Options{
		AllowOriginRequestFunc: func(r *http.Request, _ string) bool {
			err := middleware.ValidateRequestURL(r, a.sharedKey)
			if err != nil {
				log.FromRequest(r).Info().Err(err).Msg("authenticate: origin blocked")
			}
			return err == nil
		},
		AllowCredentials: true,
		AllowedHeaders:   []string{"*"},
	})
	v.Use(c.Handler)
	v.Use(middleware.ValidateSignature(a.sharedKey))
	v.Use(sessions.RetrieveSession(a.sessionLoaders...))
	v.Use(a.VerifySession)
	v.Path("/sign_in").Handler(httputil.HandlerFunc(a.SignIn))
	v.Path("/sign_out").Handler(httputil.HandlerFunc(a.SignOut))
	v.Path("/refresh").Handler(httputil.HandlerFunc(a.Refresh)).Methods(http.MethodGet)

	// programmatic access api endpoint
	api := r.PathPrefix("/api").Subrouter()
	api.Use(sessions.RetrieveSession(a.sessionLoaders...))
	api.Path("/v1/refresh").Handler(httputil.HandlerFunc(a.RefreshAPI))

	return r
}

// VerifySession is the middleware used to enforce a valid authentication
// session state is attached to the users's request context.
func (a *Authenticate) VerifySession(next http.Handler) http.Handler {
	return httputil.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		state, _, err := sessions.FromContext(r.Context())
		if errors.Is(err, sessions.ErrExpired) {
			ctx, err := a.refresh(w, r, state)
			if err != nil {
				log.FromRequest(r).Info().Err(err).Msg("authenticate: verify session, refresh")
				return a.reauthenticateOrFail(w, r, err)
			}
			next.ServeHTTP(w, r.WithContext(ctx))
			return nil
		} else if err != nil {
			log.FromRequest(r).Info().Err(err).Msg("authenticate: verify session")
			return a.reauthenticateOrFail(w, r, err)
		}
		next.ServeHTTP(w, r)
		return nil
	})
}

func (a *Authenticate) refresh(w http.ResponseWriter, r *http.Request, s *sessions.State) (context.Context, error) {
	ctx, span := trace.StartSpan(r.Context(), "authenticate.VerifySession/refresh")
	defer span.End()
	newSession, err := a.provider.Refresh(ctx, s)
	if err != nil {
		return nil, fmt.Errorf("authenticate: refresh failed: %w", err)
	}
	if err := a.sessionStore.SaveSession(w, r, newSession); err != nil {
		return nil, fmt.Errorf("authenticate: refresh save failed: %w", err)
	}
	// return the new session and add it to the current request context
	return sessions.NewContext(ctx, newSession, "", err), nil
}

// RobotsTxt handles the /robots.txt route.
func (a *Authenticate) RobotsTxt(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "User-agent: *\nDisallow: /")
}

// SignIn handles to authenticating a user.
func (a *Authenticate) SignIn(w http.ResponseWriter, r *http.Request) error {
	redirectURL, err := urlutil.ParseAndValidateURL(r.FormValue(urlutil.QueryRedirectURI))
	if err != nil {
		return httputil.NewError(http.StatusBadRequest, err)
	}

	jwtAudience := []string{a.RedirectURL.Hostname(), redirectURL.Hostname()}

	var callbackURL *url.URL
	// if the callback is explicitly set, set it and add an additional audience
	if callbackStr := r.FormValue(urlutil.QueryCallbackURI); callbackStr != "" {
		callbackURL, err = urlutil.ParseAndValidateURL(callbackStr)
		if err != nil {
			return httputil.NewError(http.StatusBadRequest, err)
		}
		jwtAudience = append(jwtAudience, callbackURL.Hostname())
	} else {
		// otherwise, assume callback is the same host as redirect
		callbackURL, _ = urlutil.DeepCopy(redirectURL)
		callbackURL.Path = "/.pomerium/callback/"
		callbackURL.RawQuery = ""
	}

	// add an additional claim for the forward-auth host, if set
	if fwdAuth := r.FormValue(urlutil.QueryForwardAuth); fwdAuth != "" {
		jwtAudience = append(jwtAudience, fwdAuth)
	}

	s, _, err := sessions.FromContext(r.Context())
	if err != nil {
		return httputil.NewError(http.StatusBadRequest, err)
	}

	// user impersonation
	if impersonate := r.FormValue(urlutil.QueryImpersonateAction); impersonate != "" {
		s.SetImpersonation(r.FormValue(urlutil.QueryImpersonateEmail), r.FormValue(urlutil.QueryImpersonateGroups))
	}

	// re-persist the session, useful when session was evicted from session
	if err := a.sessionStore.SaveSession(w, r, s); err != nil {
		return httputil.NewError(http.StatusBadRequest, err)
	}

	newSession := s.NewSession(a.RedirectURL.Host, jwtAudience)

	callbackParams := callbackURL.Query()

	if r.FormValue(urlutil.QueryIsProgrammatic) == "true" {
		newSession.Programmatic = true
		encSession, err := a.encryptedEncoder.Marshal(newSession)
		if err != nil {
			return httputil.NewError(http.StatusBadRequest, err)
		}
		callbackParams.Set(urlutil.QueryRefreshToken, string(encSession))
		callbackParams.Set(urlutil.QueryIsProgrammatic, "true")
	}

	// sign the route session, as a JWT
	signedJWT, err := a.sharedEncoder.Marshal(newSession.RouteSession())
	if err != nil {
		return httputil.NewError(http.StatusBadRequest, err)
	}

	// encrypt our route-based token JWT avoiding any accidental logging
	encryptedJWT := cryptutil.Encrypt(a.sharedCipher, signedJWT, nil)
	// base64 our encrypted payload for URL-friendlyness
	encodedJWT := base64.URLEncoding.EncodeToString(encryptedJWT)

	// add our encoded and encrypted route-session JWT to a query param
	callbackParams.Set(urlutil.QuerySessionEncrypted, encodedJWT)
	callbackParams.Set(urlutil.QueryRedirectURI, redirectURL.String())
	callbackURL.RawQuery = callbackParams.Encode()

	// build our hmac-d redirect URL with our session, pointing back to the
	// proxy's callback URL which is responsible for setting our new route-session
	uri := urlutil.NewSignedURL(a.sharedKey, callbackURL)
	httputil.Redirect(w, r, uri.String(), http.StatusFound)
	return nil
}

// SignOut signs the user out and attempts to revoke the user's identity session
// Handles both GET and POST.
func (a *Authenticate) SignOut(w http.ResponseWriter, r *http.Request) error {
	session, _, err := sessions.FromContext(r.Context())
	if err != nil {
		return httputil.NewError(http.StatusBadRequest, err)
	}
	a.sessionStore.ClearSession(w, r)
	err = a.provider.Revoke(r.Context(), session.AccessToken)
	if err != nil {
		return httputil.NewError(http.StatusBadRequest, err)
	}
	redirectURL, err := urlutil.ParseAndValidateURL(r.FormValue(urlutil.QueryRedirectURI))
	if err != nil {
		return httputil.NewError(http.StatusBadRequest, err)

	}
	httputil.Redirect(w, r, redirectURL.String(), http.StatusFound)
	return nil
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
func (a *Authenticate) reauthenticateOrFail(w http.ResponseWriter, r *http.Request, err error) error {
	// If request AJAX/XHR request, return a 401 instead .
	if reqType := r.Header.Get("X-Requested-With"); strings.EqualFold(reqType, "XmlHttpRequest") {
		return httputil.NewError(http.StatusUnauthorized, err)
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
	return nil
}

// OAuthCallback handles the callback from the identity provider.
//
// https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowSteps
// https://openid.net/specs/openid-connect-core-1_0.html#AuthResponse
func (a *Authenticate) OAuthCallback(w http.ResponseWriter, r *http.Request) error {
	redirect, err := a.getOAuthCallback(w, r)
	if err != nil {
		return fmt.Errorf("oauth callback : %w", err)
	}
	httputil.Redirect(w, r, redirect.String(), http.StatusFound)
	return nil
}

func (a *Authenticate) getOAuthCallback(w http.ResponseWriter, r *http.Request) (*url.URL, error) {
	// Error Authentication Response: rfc6749#section-4.1.2.1 & OIDC#3.1.2.6
	//
	// first, check if the identity provider returned an error
	if idpError := r.FormValue("error"); idpError != "" {
		return nil, httputil.NewError(http.StatusBadRequest, fmt.Errorf("identity provider: %v", idpError))
	}
	// fail if no session redemption code is returned
	code := r.FormValue("code")
	if code == "" {
		return nil, httputil.NewError(http.StatusBadRequest, fmt.Errorf("identity provider returned empty code"))
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
		return nil, httputil.NewError(http.StatusBadRequest, err)
	}

	// split state into concat'd components
	// (nonce|timestamp|redirect_url|encrypted_data(redirect_url)+mac(nonce,ts))
	statePayload := strings.SplitN(string(bytes), "|", 3)
	if len(statePayload) != 3 {
		return nil, httputil.NewError(http.StatusBadRequest, fmt.Errorf("state malformed, size: %d", len(statePayload)))
	}

	// verify that the returned timestamp is valid
	if err := cryptutil.ValidTimestamp(statePayload[1]); err != nil {
		return nil, httputil.NewError(http.StatusBadRequest, err)
	}

	// Use our AEAD construct to enforce secrecy and authenticity:
	// mac: to validate the nonce again, and above timestamp
	// decrypt: to prevent leaking 'redirect_uri' to IdP or logs
	b := []byte(fmt.Sprint(statePayload[0], "|", statePayload[1], "|"))
	redirectString, err := cryptutil.Decrypt(a.cookieCipher, []byte(statePayload[2]), b)
	if err != nil {
		return nil, httputil.NewError(http.StatusBadRequest, err)
	}

	redirectURL, err := urlutil.ParseAndValidateURL(string(redirectString))
	if err != nil {
		return nil, httputil.NewError(http.StatusBadRequest, err)
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
func (a *Authenticate) RefreshAPI(w http.ResponseWriter, r *http.Request) error {
	s, _, err := sessions.FromContext(r.Context())
	if err != nil && !errors.Is(err, sessions.ErrExpired) {
		return httputil.NewError(http.StatusBadRequest, err)
	}
	newSession, err := a.provider.Refresh(r.Context(), s)
	if err != nil {
		return err
	}
	newSession = newSession.NewSession(s.Issuer, s.Audience)

	encSession, err := a.encryptedEncoder.Marshal(newSession)
	if err != nil {
		return err
	}

	signedJWT, err := a.sharedEncoder.Marshal(newSession.RouteSession())
	if err != nil {
		return err
	}
	var response struct {
		JWT          string `json:"jwt"`
		RefreshToken string `json:"refresh_token"`
	}
	response.RefreshToken = string(encSession)
	response.JWT = string(signedJWT)

	jsonResponse, err := json.Marshal(&response)
	if err != nil {
		return httputil.NewError(http.StatusBadRequest, err)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonResponse)
	return nil
}

// Refresh is called by the proxy service to handle backend session refresh.
//
// NOTE: The actual refresh is handled as part of the "VerifySession"
// middleware. This handler is responsible for creating a new route scoped
// session and returning it.
func (a *Authenticate) Refresh(w http.ResponseWriter, r *http.Request) error {
	s, _, err := sessions.FromContext(r.Context())
	if err != nil {
		return httputil.NewError(http.StatusBadRequest, err)
	}

	routeSession := s.NewSession(r.Host, []string{r.Host, r.FormValue(urlutil.QueryAudience)})
	routeSession.AccessTokenID = s.AccessTokenID

	signedJWT, err := a.sharedEncoder.Marshal(routeSession.RouteSession())
	if err != nil {
		return err
	}

	w.Header().Set("Content-Type", "application/jwt") // RFC 7519 : 10.3.1
	w.Write(signedJWT)
	return nil
}
