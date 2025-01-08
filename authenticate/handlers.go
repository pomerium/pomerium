package authenticate

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/rs/cors"

	"github.com/pomerium/csrf"
	"github.com/pomerium/pomerium/internal/authenticateflow"
	"github.com/pomerium/pomerium/internal/handlers"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/middleware"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/internal/telemetry/trace"
	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	"github.com/pomerium/pomerium/pkg/identity"
	"github.com/pomerium/pomerium/pkg/identity/oidc"
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
			csrf.Secure(true),
			csrf.Path("/"),
			csrf.UnsafePaths(
				[]string{
					"/oauth2/callback", // rfc6749#section-10.12 accepts GET
				}),
			csrf.FormValueName("state"), // rfc6749#section-10.12
			csrf.CookieName(csrfKey),
			csrf.FieldName(csrfKey),
			csrf.ErrorHandler(httputil.HandlerFunc(httputil.CSRFFailureHandler)),
			csrf.SameSite(options.GetCSRFSameSite()),
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
			err := state.flow.VerifyAuthenticateSignature(r)
			if err == nil {
				log.FromRequest(r).Info().Msg("authenticate: signed URL, adding CORS headers")
			}
			return err == nil
		},
		AllowCredentials: true,
		AllowedHeaders:   []string{"*"},
	})
	sr.Use(c.Handler)
	sr.Use(a.RetrieveSession)

	// routes that don't need a session:
	sr.Path("/sign_out").Handler(httputil.HandlerFunc(a.SignOut))
	sr.Path("/signed_out").Handler(httputil.HandlerFunc(a.signedOut)).Methods(http.MethodGet)

	// routes that need a session:
	sr = sr.NewRoute().Subrouter()
	sr.Use(a.VerifySession)
	sr.Path("/").Handler(a.requireValidSignatureOnRedirect(a.userInfo))
	sr.Path("/sign_in").Handler(httputil.HandlerFunc(a.SignIn))
	sr.Path("/device-enrolled").Handler(httputil.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		handlers.DeviceEnrolled(a.getUserInfoData(r)).ServeHTTP(w, r)
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
		ctx, span := a.tracer.Start(r.Context(), "authenticate.VerifySession")
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

		if err := state.flow.VerifySession(ctx, r, sessionState); err != nil {
			log.FromRequest(r).Info().
				Err(err).
				Str("idp_id", idpID).
				Msg("authenticate: couldn't verify session")
			return a.reauthenticateOrFail(w, r, err)
		}

		next.ServeHTTP(w, r.WithContext(ctx))
		return nil
	})
}

// RobotsTxt handles the /robots.txt route.
func (a *Authenticate) RobotsTxt(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "User-agent: *\nDisallow: /")
}

// SignIn handles authenticating a user.
func (a *Authenticate) SignIn(w http.ResponseWriter, r *http.Request) error {
	ctx, span := a.tracer.Start(r.Context(), "authenticate.SignIn")
	defer span.End()

	state := a.state.Load()

	s, err := a.getSessionFromCtx(ctx)
	if err != nil {
		state.sessionStore.ClearSession(w, r)
		return err
	}

	return state.flow.SignIn(w, r, s)
}

// SignOut signs the user out and attempts to revoke the user's identity session
// Handles both GET and POST.
func (a *Authenticate) SignOut(w http.ResponseWriter, r *http.Request) error {
	// check for an HMAC'd URL. If none is found, show a confirmation page.
	err := a.state.Load().flow.VerifyAuthenticateSignature(r)
	if err != nil {
		authenticateURL, err := a.options.Load().GetAuthenticateURL()
		if err != nil {
			return err
		}

		handlers.SignOutConfirm(handlers.SignOutConfirmData{
			URL:             urlutil.SignOutURL(r, authenticateURL, a.state.Load().sharedKey),
			BrandingOptions: a.options.Load().BrandingOptions,
		}).ServeHTTP(w, r)
		return nil
	}

	// otherwise actually do the sign out
	return a.signOutRedirect(w, r)
}

func (a *Authenticate) signOutRedirect(w http.ResponseWriter, r *http.Request) error {
	ctx, span := a.tracer.Start(r.Context(), "authenticate.SignOut")
	defer span.End()

	options := a.options.Load()
	idpID := a.getIdentityProviderIDForRequest(r)

	authenticator, err := a.cfg.getIdentityProvider(ctx, a.tracerProvider, options, idpID)
	if err != nil {
		return err
	}

	rawIDToken := a.revokeSession(ctx, w, r)

	authenticateURL, err := options.GetAuthenticateURL()
	if err != nil {
		return fmt.Errorf("error getting authenticate url: %w", err)
	}

	signOutRedirectURL, err := options.GetSignOutRedirectURL()
	if err != nil {
		return err
	}

	var signOutURL string
	if uri := r.FormValue(urlutil.QueryRedirectURI); uri != "" {
		signOutURL = uri
	} else if signOutRedirectURL != nil {
		signOutURL = signOutRedirectURL.String()
	}

	authenticateSignedOutURL := authenticateURL.ResolveReference(&url.URL{
		Path: "/.pomerium/signed_out",
	}).String()

	if err := authenticator.SignOut(w, r, rawIDToken, authenticateSignedOutURL, signOutURL); err == nil {
		return nil
	} else if !errors.Is(err, oidc.ErrSignoutNotImplemented) {
		log.Ctx(r.Context()).Error().Err(err).Msg("authenticate: failed to get sign out url for authenticator")
	}

	// if the authenticator failed to sign out, and no sign out url is defined, just go to the signed out page
	if signOutURL == "" {
		signOutURL = authenticateSignedOutURL
	}

	httputil.Redirect(w, r, signOutURL, http.StatusFound)
	return nil
}

func (a *Authenticate) signedOut(w http.ResponseWriter, r *http.Request) error {
	handlers.SignedOut(handlers.SignedOutData{
		BrandingOptions: a.options.Load().BrandingOptions,
	}).ServeHTTP(w, r)
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

	state := a.state.Load()
	options := a.options.Load()
	idpID := a.getIdentityProviderIDForRequest(r)

	authenticator, err := a.cfg.getIdentityProvider(r.Context(), a.tracerProvider, options, idpID)
	if err != nil {
		return err
	}

	state.flow.LogAuthenticateEvent(r)

	state.sessionStore.ClearSession(w, r)
	redirectURL := state.redirectURL.ResolveReference(r.URL)
	redirectURLValues := redirectURL.Query()
	var traceID string
	if tp := trace.PomeriumURLQueryCarrier(redirectURLValues).Get("traceparent"); len(tp) == 55 {
		if traceIDBytes, err := hex.DecodeString(tp[3:35]); err == nil {
			traceFlags, _ := hex.DecodeString(tp[53:55])
			if len(traceFlags) != 1 {
				traceFlags = []byte{0}
			}
			traceID = base64.RawURLEncoding.EncodeToString(append(traceIDBytes, traceFlags[0]))
		}
	}
	nonce := csrf.Token(r)
	now := time.Now().Unix()
	b := []byte(fmt.Sprintf("%s|%d|%s|", nonce, now, traceID))
	enc := cryptutil.Encrypt(state.cookieCipher, []byte(redirectURL.String()), b)
	b = append(b, enc...)
	encodedState := base64.URLEncoding.EncodeToString(b)

	err = authenticator.SignIn(w, r, encodedState)
	if err != nil {
		return httputil.NewError(http.StatusInternalServerError,
			fmt.Errorf("failed to sign in: %w", err))
	}
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
	ctx, span := a.tracer.Start(r.Context(), "authenticate.getOAuthCallback")
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
	// (nonce|timestamp|trace_id+flags|encrypted_data(redirect_url)+mac(nonce,ts))
	statePayload := strings.SplitN(string(bytes), "|", 4)
	if len(statePayload) != 4 {
		return nil, httputil.NewError(http.StatusBadRequest, fmt.Errorf("state malformed, size: %d", len(statePayload)))
	}

	// Use our AEAD construct to enforce secrecy and authenticity:
	// mac: to validate the nonce again, and above timestamp
	// decrypt: to prevent leaking 'redirect_uri' to IdP or logs
	b := []byte(fmt.Sprint(statePayload[0], "|", statePayload[1], "|", statePayload[2], "|"))
	redirectString, err := cryptutil.Decrypt(state.cookieCipher, []byte(statePayload[3]), b)
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

	idpID := state.flow.GetIdentityProviderIDForURLValues(redirectURL.Query())

	authenticator, err := a.cfg.getIdentityProvider(ctx, a.tracerProvider, options, idpID)
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

	// save the session and access token to the databroker/cookie store
	if err := state.flow.PersistSession(ctx, w, &newState, claims, accessToken); err != nil {
		return nil, fmt.Errorf("failed saving new session: %w", err)
	}

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
	ctx, span := a.tracer.Start(r.Context(), "authenticate.userInfo")
	defer span.End()

	options := a.options.Load()

	r = r.WithContext(ctx)
	r = authenticateflow.GetExternalAuthenticateRequest(r, options)

	// if we came in with a redirect URI, save it to a cookie so it doesn't expire with the HMAC
	if redirectURI := r.FormValue(urlutil.QueryRedirectURI); redirectURI != "" {
		u := urlutil.GetAbsoluteURL(r)
		u.RawQuery = ""

		cookie := options.NewCookie()
		cookie.Name = urlutil.QueryRedirectURI
		cookie.Value = redirectURI

		http.SetCookie(w, cookie)
		http.Redirect(w, r, u.String(), http.StatusFound)
		return nil
	}

	handlers.UserInfo(a.getUserInfoData(r)).ServeHTTP(w, r)
	return nil
}

func (a *Authenticate) getUserInfoData(r *http.Request) handlers.UserInfoData {
	state := a.state.Load()

	s, err := a.getSessionFromCtx(r.Context())
	if err != nil {
		s.ID = uuid.New().String()
	}

	data := state.flow.GetUserInfoData(r, s)
	data.CSRFToken = csrf.Token(r)
	data.BrandingOptions = a.options.Load().BrandingOptions
	return data
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

	authenticator, err := a.cfg.getIdentityProvider(ctx, a.tracerProvider, options, idpID)
	if err != nil {
		return ""
	}

	sessionState, _ := a.getSessionFromCtx(ctx)

	return state.flow.RevokeSession(ctx, r, authenticator, sessionState)
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
	return a.state.Load().flow.GetIdentityProviderIDForURLValues(r.Form)
}
