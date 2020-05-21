package authenticate

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

	"github.com/pomerium/csrf"
	"github.com/pomerium/pomerium/internal/cryptutil"
	"github.com/pomerium/pomerium/internal/hashutil"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/identity/oidc"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/middleware"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/internal/telemetry/trace"
	"github.com/pomerium/pomerium/internal/urlutil"

	"github.com/gorilla/mux"
	"github.com/rs/cors"
	"golang.org/x/oauth2"
)

// Handler returns the authenticate service's handler chain.
func (a *Authenticate) Handler() http.Handler {
	r := httputil.NewRouter()
	a.Mount(r)
	return r
}

// Mount mounts the authenticate routes to the given router.
func (a *Authenticate) Mount(r *mux.Router) {
	r.StrictSlash(true)
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

	wk := r.PathPrefix("/.well-known/pomerium").Subrouter()
	wk.Path("/jwks.json").Handler(httputil.HandlerFunc(a.jwks)).Methods(http.MethodGet)
	wk.Path("/").Handler(httputil.HandlerFunc(a.wellKnown)).Methods(http.MethodGet)

	// https://www.googleapis.com/oauth2/v3/certs

	// programmatic access api endpoint
	api := r.PathPrefix("/api").Subrouter()
	api.Use(sessions.RetrieveSession(a.sessionLoaders...))
	api.Path("/v1/refresh").Handler(httputil.HandlerFunc(a.RefreshAPI))
}

// Well-Known Uniform Resource Identifiers (URIs)
// https://en.wikipedia.org/wiki/List_of_/.well-known/_services_offered_by_webservers
func (a *Authenticate) wellKnown(w http.ResponseWriter, r *http.Request) error {
	wellKnownURLS := struct {
		// URL string referencing the client's JSON Web Key (JWK) Set
		// RFC7517 document, which contains the client's public keys.
		JSONWebWeySetURL       string `json:"jwks_uri"`
		OAuth2Callback         string `json:"authentication_callback_endpoint"`
		ProgrammaticRefreshAPI string `json:"api_refresh_endpoint"`
	}{
		a.RedirectURL.ResolveReference(&url.URL{Path: "/.well-known/pomerium/jwks.json"}).String(),
		a.RedirectURL.ResolveReference(&url.URL{Path: "/oauth2/callback"}).String(),
		a.RedirectURL.ResolveReference(&url.URL{Path: "/api/v1/refresh"}).String(),
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	jBytes, err := json.Marshal(wellKnownURLS)
	if err != nil {
		return err
	}
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "%s", jBytes)
	return nil
}

func (a *Authenticate) jwks(w http.ResponseWriter, r *http.Request) error {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	jBytes, err := json.Marshal(a.jwk)
	if err != nil {
		return err
	}
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "%s", jBytes)
	return nil
}

// VerifySession is the middleware used to enforce a valid authentication
// session state is attached to the users's request context.
func (a *Authenticate) VerifySession(next http.Handler) http.Handler {
	return httputil.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := trace.StartSpan(r.Context(), "authenticate.VerifySession")
		defer span.End()
		s, err := a.getSessionFromCtx(ctx)
		if err != nil {
			log.FromRequest(r).Info().Err(err).Msg("authenticate: session load error")
			return a.reauthenticateOrFail(w, r, err)
		}
		if s.IsExpired() {
			ctx, err = a.refresh(w, r, s)
			if err != nil {
				log.FromRequest(r).Info().Err(err).Msg("authenticate: verify session, refresh")
				return a.reauthenticateOrFail(w, r, err)
			}
		}
		next.ServeHTTP(w, r.WithContext(ctx))
		return nil
	})
}

func (a *Authenticate) refresh(w http.ResponseWriter, r *http.Request, s *sessions.State) (context.Context, error) {
	ctx, span := trace.StartSpan(r.Context(), "authenticate.VerifySession/refresh")
	defer span.End()
	accessToken, err := a.getAccessToken(ctx, s)
	if err != nil {
		return nil, err
	}

	// we are going to keep the same audiences for the refreshed token
	// otherwise this will be rewritten to be the ClientID of the provider
	oldAudience := s.Audience

	newAccessToken, err := a.provider.Refresh(ctx, accessToken, s)
	if err != nil {
		return nil, fmt.Errorf("authenticate: refresh failed: %w", err)
	}

	newSession := sessions.NewSession(s, a.RedirectURL.Hostname(), oldAudience, newAccessToken)

	encSession, err := a.sharedEncoder.Marshal(newSession)
	if err != nil {
		return nil, err
	}

	if err := a.sessionStore.SaveSession(w, r, newSession); err != nil {
		return nil, fmt.Errorf("authenticate: error saving new session: %w", err)
	}

	if err := a.setAccessToken(ctx, newAccessToken); err != nil {
		return nil, fmt.Errorf("authenticate: error saving refreshed access token: %w", err)
	}
	// return the new session and add it to the current request context
	return sessions.NewContext(ctx, string(encSession), err), nil
}

// RobotsTxt handles the /robots.txt route.
func (a *Authenticate) RobotsTxt(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "User-agent: *\nDisallow: /")
}

// SignIn handles authenticating a user.
func (a *Authenticate) SignIn(w http.ResponseWriter, r *http.Request) error {
	ctx, span := trace.StartSpan(r.Context(), "authenticate.SignOut")
	defer span.End()

	redirectURL, err := urlutil.ParseAndValidateURL(r.FormValue(urlutil.QueryRedirectURI))
	if err != nil {
		return httputil.NewError(http.StatusBadRequest, err)
	}

	jwtAudience := []string{a.RedirectURL.Host, redirectURL.Host}

	var callbackURL *url.URL
	// if the callback is explicitly set, set it and add an additional audience
	if callbackStr := r.FormValue(urlutil.QueryCallbackURI); callbackStr != "" {
		callbackURL, err = urlutil.ParseAndValidateURL(callbackStr)
		if err != nil {
			return httputil.NewError(http.StatusBadRequest, err)
		}
		jwtAudience = append(jwtAudience, callbackURL.Host)
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

	s, err := a.getSessionFromCtx(ctx)
	if err != nil {
		return err
	}
	accessToken, err := a.getAccessToken(ctx, s)
	if err != nil {
		return err
	}
	// user impersonation
	if impersonate := r.FormValue(urlutil.QueryImpersonateAction); impersonate != "" {
		s.SetImpersonation(r.FormValue(urlutil.QueryImpersonateEmail), r.FormValue(urlutil.QueryImpersonateGroups))
	}
	newSession := sessions.NewSession(s, a.RedirectURL.Host, jwtAudience, accessToken)

	// re-persist the session, useful when session was evicted from session
	if err := a.sessionStore.SaveSession(w, r, s); err != nil {
		return httputil.NewError(http.StatusBadRequest, err)
	}

	callbackParams := callbackURL.Query()

	if r.FormValue(urlutil.QueryIsProgrammatic) == "true" {
		newSession.Programmatic = true
		encSession, err := a.encryptedEncoder.Marshal(accessToken)
		if err != nil {
			return httputil.NewError(http.StatusBadRequest, err)
		}
		callbackParams.Set(urlutil.QueryRefreshToken, string(encSession))
		callbackParams.Set(urlutil.QueryIsProgrammatic, "true")
	}

	// sign the route session, as a JWT
	signedJWT, err := a.sharedEncoder.Marshal(newSession)
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
	ctx, span := trace.StartSpan(r.Context(), "authenticate.SignOut")
	defer span.End()

	// no matter what happens, we want to clear the session store
	a.sessionStore.ClearSession(w, r)
	redirectString := r.FormValue(urlutil.QueryRedirectURI)
	endSessionURL, err := a.provider.LogOut()
	if err == nil {
		params := url.Values{}
		params.Add("post_logout_redirect_uri", redirectString)
		endSessionURL.RawQuery = params.Encode()
		redirectString = endSessionURL.String()
	} else if !errors.Is(err, oidc.ErrSignoutNotImplemented) {
		log.Warn().Err(err).Msg("authenticate.SignOut: failed getting session")
	}

	httputil.Redirect(w, r, redirectString, http.StatusFound)

	s, err := a.getSessionFromCtx(ctx)
	if err != nil {
		log.Warn().Err(err).Msg("authenticate.SignOut: failed getting session")
		return nil
	}

	accessToken, err := a.getAccessToken(ctx, s)
	if err != nil {
		log.Warn().Err(err).Msg("authenticate.SignOut: failed getting access token")
		return nil
	}

	// first, try to revoke the session if implemented
	err = a.provider.Revoke(ctx, accessToken)
	if err != nil && !errors.Is(err, oidc.ErrRevokeNotImplemented) {
		log.Warn().Err(err).Msg("authenticate.SignOut: failed revoking token")
		return nil
	}
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
	// If request AJAX/XHR request, return a 401 instead because the redirect
	// will almost certainly violate their CORs policy
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
		return fmt.Errorf("authenticate.OAuthCallback: %w", err)
	}
	httputil.Redirect(w, r, redirect.String(), http.StatusFound)
	return nil
}

func (a *Authenticate) statusForErrorCode(errorCode string) int {
	switch errorCode {
	case "access_denied", "unauthorized_client":
		return http.StatusUnauthorized
	default:
		return http.StatusBadRequest
	}
}

func (a *Authenticate) getOAuthCallback(w http.ResponseWriter, r *http.Request) (*url.URL, error) {
	ctx, span := trace.StartSpan(r.Context(), "authenticate.getOAuthCallback")
	defer span.End()

	// Error Authentication Response: rfc6749#section-4.1.2.1 & OIDC#3.1.2.6
	//
	// first, check if the identity provider returned an error
	if idpError := r.FormValue("error"); idpError != "" {
		return nil, httputil.NewError(a.statusForErrorCode(idpError), fmt.Errorf("identity provider: %v", idpError))
	}
	// fail if no session redemption code is returned
	code := r.FormValue("code")
	if code == "" {
		return nil, httputil.NewError(http.StatusBadRequest, fmt.Errorf("identity provider returned empty code"))
	}

	// Successful Authentication Response: rfc6749#section-4.1.2 & OIDC#3.1.2.5
	//
	// Exchange the supplied Authorization Code for a valid user session.
	var s sessions.State
	accessToken, err := a.provider.Authenticate(ctx, code, &s)
	if err != nil {
		return nil, fmt.Errorf("error redeeming authenticate code: %w", err)
	}

	newState := sessions.NewSession(
		&s,
		a.RedirectURL.Hostname(),
		[]string{a.RedirectURL.Hostname()},
		accessToken)

	// state includes a csrf nonce (validated by middleware) and redirect uri
	bytes, err := base64.URLEncoding.DecodeString(r.FormValue("state"))
	if err != nil {
		return nil, httputil.NewError(http.StatusBadRequest, fmt.Errorf("bad bytes: %w", err))
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

	// Ok -- We've got a valid session here. Let's now persist the access
	// token to cache ...
	if err := a.setAccessToken(ctx, accessToken); err != nil {
		return nil, fmt.Errorf("failed saving access token: %w", err)
	}
	// ...  and the user state to local storage.
	if err := a.sessionStore.SaveSession(w, r, &newState); err != nil {
		return nil, fmt.Errorf("failed saving new session: %w", err)
	}
	return redirectURL, nil
}

// RefreshAPI loads a global state, and attempts to refresh the session's access
// tokens and state with the identity provider. If successful, a new signed JWT
// and refresh token (`refresh_token`) are returned as JSON
func (a *Authenticate) RefreshAPI(w http.ResponseWriter, r *http.Request) error {
	ctx, span := trace.StartSpan(r.Context(), "authenticate.RefreshAPI")
	defer span.End()

	s, err := a.getSessionFromCtx(ctx)
	if err != nil {
		return err
	}

	accessToken, err := a.getAccessToken(ctx, s)
	if err != nil {
		return err
	}

	newAccessToken, err := a.provider.Refresh(ctx, accessToken, s)
	if err != nil {
		return err
	}

	routeNewSession := sessions.NewSession(s, a.RedirectURL.Hostname(), s.Audience, newAccessToken)

	encSession, err := a.encryptedEncoder.Marshal(accessToken)
	if err != nil {
		return err
	}

	signedJWT, err := a.sharedEncoder.Marshal(routeNewSession)
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
// middleware. This handler is simply responsible for returning that jwt.
func (a *Authenticate) Refresh(w http.ResponseWriter, r *http.Request) error {
	ctx, span := trace.StartSpan(r.Context(), "authenticate.Refresh")
	defer span.End()
	jwt, err := sessions.FromContext(ctx)
	if err != nil {
		return fmt.Errorf("authenticate.Refresh: %w", err)
	}
	w.Header().Set("Content-Type", "application/jwt") // RFC 7519 : 10.3.1
	fmt.Fprint(w, jwt)
	return nil
}

// getAccessToken gets an associated oauth2 access token from a session state
func (a *Authenticate) getAccessToken(ctx context.Context, s *sessions.State) (*oauth2.Token, error) {
	ctx, span := trace.StartSpan(ctx, "authenticate.getAccessToken")
	defer span.End()

	var accessToken oauth2.Token
	tokenBytes, err := a.cacheClient.Get(ctx, s.AccessTokenHash)
	if err != nil {
		return nil, err
	}
	if err := a.encryptedEncoder.Unmarshal(tokenBytes, &accessToken); err != nil {
		return nil, err
	}
	if accessToken.Valid() {
		return &accessToken, nil // this token is still valid, use it!
	}
	tokenBytes, err = a.cacheClient.Get(ctx, a.timestampedHash(accessToken.RefreshToken))
	if err == nil {
		// we found another possibly newer access token associated with the
		// existing refresh token so let's try that.
		if err := a.encryptedEncoder.Unmarshal(tokenBytes, &accessToken); err != nil {
			return nil, err
		}
	}

	return &accessToken, nil
}

func (a *Authenticate) setAccessToken(ctx context.Context, accessToken *oauth2.Token) error {
	encToken, err := a.encryptedEncoder.Marshal(accessToken)
	if err != nil {
		return err
	}
	// set this specific access token
	key := fmt.Sprintf("%x", hashutil.Hash(accessToken))
	if err := a.cacheClient.Set(ctx, key, encToken); err != nil {
		return fmt.Errorf("authenticate: setAccessToken failed key: %s :%w", key, err)
	}

	// set this as the "latest" token for this access token
	key = a.timestampedHash(accessToken.RefreshToken)
	if err := a.cacheClient.Set(ctx, key, encToken); err != nil {
		return fmt.Errorf("authenticate: setAccessToken failed key: %s :%w", key, err)
	}

	return nil
}

func (a *Authenticate) timestampedHash(s string) string {
	return fmt.Sprintf("%x-%v", hashutil.Hash(s), time.Now().Truncate(time.Minute).Unix())
}

func (a *Authenticate) getSessionFromCtx(ctx context.Context) (*sessions.State, error) {
	jwt, err := sessions.FromContext(ctx)
	if err != nil {
		return nil, httputil.NewError(http.StatusBadRequest, err)
	}
	var s sessions.State
	if err := a.sharedEncoder.Unmarshal([]byte(jwt), &s); err != nil {
		return nil, httputil.NewError(http.StatusBadRequest, err)
	}
	return &s, nil
}
