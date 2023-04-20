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

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/rs/cors"
	"golang.org/x/oauth2"

	"github.com/pomerium/csrf"
	"github.com/pomerium/pomerium/internal/handlers"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/identity"
	"github.com/pomerium/pomerium/internal/identity/oauth/apple"
	"github.com/pomerium/pomerium/internal/identity/oidc"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/middleware"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/internal/telemetry/trace"
	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	"github.com/pomerium/pomerium/pkg/hpke"
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
	r.Use(func(h http.Handler) http.Handler {
		options := a.options.Load()
		state := a.state.Load()
		csrfKey := fmt.Sprintf("%s_csrf", options.CookieName)
		csrfOptions := []csrf.Option{
			csrf.Secure(options.CookieSecure),
			csrf.Path("/"),
			csrf.UnsafePaths(
				[]string{
					"/oauth2/callback", // rfc6749#section-10.12 accepts GET
				}),
			csrf.FormValueName("state"), // rfc6749#section-10.12
			csrf.CookieName(csrfKey),
			csrf.FieldName(csrfKey),
			csrf.ErrorHandler(httputil.HandlerFunc(httputil.CSRFFailureHandler)),
		}

		if options.Provider == apple.Name {
			// csrf.SameSiteLaxMode will cause browsers to reset
			// the session on POST. This breaks Appleid being able
			// to verify the csrf token.
			csrfOptions = append(csrfOptions, csrf.SameSite(csrf.SameSiteNoneMode))
		} else {
			csrfOptions = append(csrfOptions, csrf.SameSite(csrf.SameSiteLaxMode))
		}

		return csrf.Protect(state.cookieSecret, csrfOptions...)(h)
	})

	// redirect / to /.pomerium/
	r.Path("/").Handler(http.RedirectHandler("/.pomerium/", http.StatusFound))

	r.Path("/robots.txt").HandlerFunc(a.RobotsTxt).Methods(http.MethodGet)
	// Identity Provider (IdP) endpoints
	r.Path("/oauth2/callback").Handler(httputil.HandlerFunc(a.OAuthCallback)).Methods(http.MethodGet, http.MethodPost)

	a.mountDashboard(r)
}

func (a *Authenticate) mountDashboard(r *mux.Router) {
	sr := httputil.DashboardSubrouter(r)
	c := cors.New(cors.Options{
		AllowOriginRequestFunc: func(r *http.Request, _ string) bool {
			state := a.state.Load()
			err := middleware.ValidateRequestURL(a.getExternalRequest(r), state.sharedKey)
			if err != nil {
				log.FromRequest(r).Info().Err(err).Msg("authenticate: origin blocked")
			}
			return err == nil
		},
		AllowCredentials: true,
		AllowedHeaders:   []string{"*"},
	})
	sr.Use(c.Handler)

	// routes that don't need a session:
	sr.Path("/sign_out").Handler(httputil.HandlerFunc(a.SignOut))

	// routes that need a session:
	sr = sr.NewRoute().Subrouter()
	sr.Use(a.RetrieveSession)
	sr.Use(a.VerifySession)
	sr.Path("/").Handler(a.requireValidSignatureOnRedirect(a.userInfo))
	sr.Path("/sign_in").Handler(httputil.HandlerFunc(a.SignIn))
	sr.Path("/device-enrolled").Handler(httputil.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		userInfoData, err := a.getUserInfoData(r)
		if err != nil {
			return err
		}

		handlers.DeviceEnrolled(userInfoData).ServeHTTP(w, r)
		return nil
	}))

	cr := sr.PathPrefix("/callback").Subrouter()
	cr.Path("/").Handler(a.requireValidSignature(a.Callback)).Methods(http.MethodGet)
}

// RetrieveSession is the middleware used retrieve session by the sessionLoader
func (a *Authenticate) RetrieveSession(next http.Handler) http.Handler {
	return sessions.RetrieveSession(a.state.Load().sessionLoader)(next)
}

// VerifySession is the middleware used to enforce a valid authentication
// session state is attached to the users's request context.
func (a *Authenticate) VerifySession(next http.Handler) http.Handler {
	return httputil.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := trace.StartSpan(r.Context(), "authenticate.VerifySession")
		defer span.End()

		state := a.state.Load()
		idpID := a.getIdentityProviderIDForRequest(r)

		sessionState, err := a.getSessionFromCtx(ctx)
		if err != nil {
			log.FromRequest(r).Info().
				Err(err).
				Str("idp_id", idpID).
				Msg("authenticate: session load error")
			return a.reauthenticateOrFail(w, r, err)
		}

		if sessionState.IdentityProviderID != idpID {
			log.FromRequest(r).Info().
				Str("idp_id", idpID).
				Str("session_idp_id", sessionState.IdentityProviderID).
				Str("id", sessionState.ID).
				Msg("authenticate: session not associated with identity provider")
			return a.reauthenticateOrFail(w, r, err)
		}

		_, err = loadIdentityProfile(r, state.cookieCipher)
		if err != nil {
			log.FromRequest(r).Info().
				Err(err).
				Str("idp_id", idpID).
				Msg("authenticate: identity profile load error")
			return a.reauthenticateOrFail(w, r, err)
		}

		next.ServeHTTP(w, r.WithContext(ctx))
		return nil
	})
}

// RobotsTxt handles the /robots.txt route.
func (a *Authenticate) RobotsTxt(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "User-agent: *\nDisallow: /")
}

// SignIn handles authenticating a user.
func (a *Authenticate) SignIn(w http.ResponseWriter, r *http.Request) error {
	ctx, span := trace.StartSpan(r.Context(), "authenticate.SignIn")
	defer span.End()

	state := a.state.Load()

	if err := r.ParseForm(); err != nil {
		return httputil.NewError(http.StatusBadRequest, err)
	}
	proxyPublicKey, requestParams, err := hpke.DecryptURLValues(state.hpkePrivateKey, r.Form)
	if err != nil {
		return err
	}

	idpID := requestParams.Get(urlutil.QueryIdentityProviderID)

	s, err := a.getSessionFromCtx(ctx)
	if err != nil {
		state.sessionStore.ClearSession(w, r)
		return err
	}

	// start over if this is a different identity provider
	if s == nil || s.IdentityProviderID != idpID {
		s = sessions.NewState(idpID)
	}

	// re-persist the session, useful when session was evicted from session
	if err := state.sessionStore.SaveSession(w, r, s); err != nil {
		return httputil.NewError(http.StatusBadRequest, err)
	}

	profile, err := loadIdentityProfile(r, state.cookieCipher)
	if err != nil {
		return httputil.NewError(http.StatusBadRequest, err)
	}

	if a.cfg.profileTrimFn != nil {
		a.cfg.profileTrimFn(profile)
	}

	redirectTo, err := urlutil.CallbackURL(state.hpkePrivateKey, proxyPublicKey, requestParams, profile)
	if err != nil {
		return httputil.NewError(http.StatusInternalServerError, err)
	}

	httputil.Redirect(w, r, redirectTo, http.StatusFound)
	return nil
}

// SignOut signs the user out and attempts to revoke the user's identity session
// Handles both GET and POST.
func (a *Authenticate) SignOut(w http.ResponseWriter, r *http.Request) error {
	// check for an HMAC'd URL. If none is found, show a confirmation page.
	err := middleware.ValidateRequestURL(a.getExternalRequest(r), a.state.Load().sharedKey)
	if err != nil {
		authenticateURL, err := a.options.Load().GetAuthenticateURL()
		if err != nil {
			return err
		}

		handlers.SignOutConfirm(handlers.SignOutConfirmData{
			URL: urlutil.SignOutURL(r, authenticateURL, a.state.Load().sharedKey),
		}).ServeHTTP(w, r)
		return nil
	}

	// otherwise actually do the sign out
	return a.signOutRedirect(w, r)
}

func (a *Authenticate) signOutRedirect(w http.ResponseWriter, r *http.Request) error {
	ctx, span := trace.StartSpan(r.Context(), "authenticate.SignOut")
	defer span.End()

	options := a.options.Load()
	idpID := a.getIdentityProviderIDForRequest(r)

	authenticator, err := a.cfg.getIdentityProvider(options, idpID)
	if err != nil {
		return err
	}

	rawIDToken := a.revokeSession(ctx, w, r)

	redirectString := ""
	signOutURL, err := options.GetSignOutRedirectURL()
	if err != nil {
		return err
	}
	if signOutURL != nil {
		redirectString = signOutURL.String()
	}
	if uri := r.FormValue(urlutil.QueryRedirectURI); uri != "" {
		redirectString = uri
	}

	endSessionURL, err := authenticator.LogOut()
	if err == nil && redirectString != "" {
		params := url.Values{}
		params.Add("id_token_hint", rawIDToken)
		params.Add("post_logout_redirect_uri", redirectString)
		endSessionURL.RawQuery = params.Encode()
		redirectString = endSessionURL.String()
	} else if err != nil && !errors.Is(err, oidc.ErrSignoutNotImplemented) {
		log.Warn(r.Context()).Err(err).Msg("authenticate.SignOut: failed getting session")
	}
	if redirectString != "" {
		httputil.Redirect(w, r, redirectString, http.StatusFound)
		return nil
	}
	return httputil.NewError(http.StatusOK, errors.New("user logged out"))
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

	state := a.state.Load()
	options := a.options.Load()
	idpID := a.getIdentityProviderIDForRequest(r)

	authenticator, err := a.cfg.getIdentityProvider(options, idpID)
	if err != nil {
		return err
	}

	state.sessionStore.ClearSession(w, r)
	redirectURL := state.redirectURL.ResolveReference(r.URL)
	nonce := csrf.Token(r)
	now := time.Now().Unix()
	b := []byte(fmt.Sprintf("%s|%d|", nonce, now))
	enc := cryptutil.Encrypt(state.cookieCipher, []byte(redirectURL.String()), b)
	b = append(b, enc...)
	encodedState := base64.URLEncoding.EncodeToString(b)
	signinURL, err := authenticator.GetSignInURL(encodedState)
	if err != nil {
		return httputil.NewError(http.StatusInternalServerError,
			fmt.Errorf("failed to get sign in url: %w", err))
	}
	httputil.Redirect(w, r, signinURL, http.StatusFound)
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

	state := a.state.Load()
	options := a.options.Load()

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

	// Use our AEAD construct to enforce secrecy and authenticity:
	// mac: to validate the nonce again, and above timestamp
	// decrypt: to prevent leaking 'redirect_uri' to IdP or logs
	b := []byte(fmt.Sprint(statePayload[0], "|", statePayload[1], "|"))
	redirectString, err := cryptutil.Decrypt(state.cookieCipher, []byte(statePayload[2]), b)
	if err != nil {
		return nil, httputil.NewError(http.StatusBadRequest, err)
	}

	redirectURL, err := urlutil.ParseAndValidateURL(string(redirectString))
	if err != nil {
		return nil, httputil.NewError(http.StatusBadRequest, err)
	}

	// verify that the returned timestamp is valid
	if err := cryptutil.ValidTimestamp(statePayload[1]); err != nil {
		return nil, httputil.NewError(http.StatusBadRequest, err).WithDescription(fmt.Sprintf(`
The request expired. This may be because a login attempt took too long, or because the server's clock is out of sync.

Try again by following this link: [%s](%s).

Or contact your administrator.
`, redirectURL.String(), redirectURL.String()))
	}

	idpID := a.getIdentityProviderIDForURLValues(redirectURL.Query())

	authenticator, err := a.cfg.getIdentityProvider(options, idpID)
	if err != nil {
		return nil, err
	}

	// Successful Authentication Response: rfc6749#section-4.1.2 & OIDC#3.1.2.5
	//
	// Exchange the supplied Authorization Code for a valid user session.
	var claims identity.SessionClaims
	accessToken, err := authenticator.Authenticate(ctx, code, &claims)
	if err != nil {
		return nil, fmt.Errorf("error redeeming authenticate code: %w", err)
	}

	s := sessions.NewState(idpID)
	err = claims.Claims.Claims(&s)
	if err != nil {
		return nil, fmt.Errorf("error unmarshaling session state: %w", err)
	}

	newState := s.WithNewIssuer(state.redirectURL.Hostname(), []string{state.redirectURL.Hostname()})
	if nextRedirectURL, err := urlutil.ParseAndValidateURL(redirectURL.Query().Get(urlutil.QueryRedirectURI)); err == nil {
		newState.Audience = append(newState.Audience, nextRedirectURL.Hostname())
	}

	// save the session and access token to the databroker
	profile, err := a.buildIdentityProfile(ctx, r, &newState, claims, accessToken)
	if err != nil {
		return nil, httputil.NewError(http.StatusInternalServerError, err)
	}
	storeIdentityProfile(w, state.cookieCipher, profile)

	// ...  and the user state to local storage.
	if err := state.sessionStore.SaveSession(w, r, &newState); err != nil {
		return nil, fmt.Errorf("failed saving new session: %w", err)
	}
	return redirectURL, nil
}

func (a *Authenticate) getSessionFromCtx(ctx context.Context) (*sessions.State, error) {
	state := a.state.Load()

	jwt, err := sessions.FromContext(ctx)
	if err != nil {
		return nil, httputil.NewError(http.StatusBadRequest, err)
	}
	var s sessions.State
	if err := state.sharedEncoder.Unmarshal([]byte(jwt), &s); err != nil {
		return nil, httputil.NewError(http.StatusBadRequest, err)
	}
	return &s, nil
}

func (a *Authenticate) userInfo(w http.ResponseWriter, r *http.Request) error {
	ctx, span := trace.StartSpan(r.Context(), "authenticate.userInfo")
	defer span.End()
	r = r.WithContext(ctx)
	r = a.getExternalRequest(r)

	// if we came in with a redirect URI, save it to a cookie so it doesn't expire with the HMAC
	if redirectURI := r.FormValue(urlutil.QueryRedirectURI); redirectURI != "" {
		u := urlutil.GetAbsoluteURL(r)
		u.RawQuery = ""

		http.SetCookie(w, &http.Cookie{
			Name:  urlutil.QueryRedirectURI,
			Value: redirectURI,
		})
		http.Redirect(w, r, u.String(), http.StatusFound)
		return nil
	}

	userInfoData, err := a.getUserInfoData(r)
	if err != nil {
		return err
	}

	handlers.UserInfo(userInfoData).ServeHTTP(w, r)
	return nil
}

func (a *Authenticate) getUserInfoData(r *http.Request) (handlers.UserInfoData, error) {
	state := a.state.Load()

	s, err := a.getSessionFromCtx(r.Context())
	if err != nil {
		s.ID = uuid.New().String()
	}

	profile, _ := loadIdentityProfile(r, state.cookieCipher)

	data := handlers.UserInfoData{
		CSRFToken: csrf.Token(r),
		Profile:   profile,

		BrandingOptions: a.options.Load().BrandingOptions,
	}
	return data, nil
}

// revokeSession always clears the local session and tries to revoke the associated session stored in the
// databroker. If successful, it returns the original `id_token` of the session, if failed, returns
// and empty string.
func (a *Authenticate) revokeSession(ctx context.Context, w http.ResponseWriter, r *http.Request) string {
	state := a.state.Load()
	options := a.options.Load()

	// clear the user's local session no matter what
	defer state.sessionStore.ClearSession(w, r)

	idpID := r.FormValue(urlutil.QueryIdentityProviderID)

	authenticator, err := a.cfg.getIdentityProvider(options, idpID)
	if err != nil {
		return ""
	}

	profile, err := loadIdentityProfile(r, a.state.Load().cookieCipher)
	if err != nil {
		return ""
	}

	oauthToken := new(oauth2.Token)
	_ = json.Unmarshal(profile.GetOauthToken(), oauthToken)
	if err := authenticator.Revoke(ctx, oauthToken); err != nil {
		log.Ctx(ctx).Warn().Err(err).Msg("authenticate: failed to revoke access token")
	}

	return string(profile.GetIdToken())
}

// Callback handles the result of a successful call to the authenticate service
// and is responsible setting per-route sessions.
func (a *Authenticate) Callback(w http.ResponseWriter, r *http.Request) error {
	redirectURLString := r.FormValue(urlutil.QueryRedirectURI)
	encryptedSession := r.FormValue(urlutil.QuerySessionEncrypted)

	redirectURL, err := urlutil.ParseAndValidateURL(redirectURLString)
	if err != nil {
		return httputil.NewError(http.StatusBadRequest, err)
	}

	rawJWT, err := a.saveCallbackSession(w, r, encryptedSession)
	if err != nil {
		return httputil.NewError(http.StatusBadRequest, err)
	}

	// if programmatic, encode the session jwt as a query param
	if isProgrammatic := r.FormValue(urlutil.QueryIsProgrammatic); isProgrammatic == "true" {
		q := redirectURL.Query()
		q.Set(urlutil.QueryPomeriumJWT, string(rawJWT))
		redirectURL.RawQuery = q.Encode()
	}
	httputil.Redirect(w, r, redirectURL.String(), http.StatusFound)
	return nil
}

// saveCallbackSession takes an encrypted per-route session token, decrypts
// it using the shared service key, then stores it the local session store.
func (a *Authenticate) saveCallbackSession(w http.ResponseWriter, r *http.Request, enctoken string) ([]byte, error) {
	state := a.state.Load()

	// 1. extract the base64 encoded and encrypted JWT from query params
	encryptedJWT, err := base64.URLEncoding.DecodeString(enctoken)
	if err != nil {
		return nil, fmt.Errorf("proxy: malfromed callback token: %w", err)
	}
	// 2. decrypt the JWT using the cipher using the _shared_ secret key
	rawJWT, err := cryptutil.Decrypt(state.sharedCipher, encryptedJWT, nil)
	if err != nil {
		return nil, fmt.Errorf("proxy: callback token decrypt error: %w", err)
	}
	// 3. Save the decrypted JWT to the session store directly as a string, without resigning
	if err = state.sessionStore.SaveSession(w, r, rawJWT); err != nil {
		return nil, fmt.Errorf("proxy: callback session save failure: %w", err)
	}
	return rawJWT, nil
}

func (a *Authenticate) getIdentityProviderIDForRequest(r *http.Request) string {
	if err := r.ParseForm(); err != nil {
		return ""
	}
	return a.getIdentityProviderIDForURLValues(r.Form)
}

func (a *Authenticate) getIdentityProviderIDForURLValues(vs url.Values) string {
	state := a.state.Load()
	idpID := ""
	if _, requestParams, err := hpke.DecryptURLValues(state.hpkePrivateKey, vs); err == nil {
		if idpID == "" {
			idpID = requestParams.Get(urlutil.QueryIdentityProviderID)
		}
	}
	if idpID == "" {
		idpID = vs.Get(urlutil.QueryIdentityProviderID)
	}
	return idpID
}
