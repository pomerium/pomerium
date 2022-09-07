package authenticate

import (
	"context"
	"encoding/base64"
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
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/csrf"
	"github.com/pomerium/pomerium/authenticate/handlers"
	"github.com/pomerium/pomerium/authenticate/handlers/webauthn"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/identity"
	"github.com/pomerium/pomerium/internal/identity/manager"
	"github.com/pomerium/pomerium/internal/identity/oidc"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/middleware"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/internal/telemetry/trace"
	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/directory"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpc/user"
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
		return csrf.Protect(
			state.cookieSecret,
			csrf.Secure(options.CookieSecure),
			csrf.Path("/"),
			csrf.UnsafePaths(
				[]string{
					"/oauth2/callback", // rfc6749#section-10.12 accepts GET
				}),
			csrf.FormValueName("state"), // rfc6749#section-10.12
			csrf.CookieName(csrfKey),
			csrf.FieldName(csrfKey),
			csrf.SameSite(csrf.SameSiteLaxMode),
			csrf.ErrorHandler(httputil.HandlerFunc(httputil.CSRFFailureHandler)),
		)(h)
	})

	// redirect / to /.pomerium/
	r.Path("/").Handler(http.RedirectHandler("/.pomerium/", http.StatusFound))

	r.Path("/robots.txt").HandlerFunc(a.RobotsTxt).Methods(http.MethodGet)
	// Identity Provider (IdP) endpoints
	r.Path("/oauth2/callback").Handler(httputil.HandlerFunc(a.OAuthCallback)).Methods(http.MethodGet)

	a.mountDashboard(r)
	a.mountWellKnown(r)
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
	sr.Use(a.RetrieveSession)
	sr.Use(a.VerifySession)
	sr.Path("/").Handler(a.requireValidSignatureOnRedirect(a.userInfo))
	sr.Path("/sign_in").Handler(a.requireValidSignature(a.SignIn))
	sr.Path("/sign_out").Handler(httputil.HandlerFunc(a.SignOut))
	sr.Path("/webauthn").Handler(a.webauthn)
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

func (a *Authenticate) mountWellKnown(r *mux.Router) {
	r.Path("/.well-known/pomerium/jwks.json").Handler(cors.AllowAll().Handler(httputil.HandlerFunc(a.jwks))).Methods(http.MethodGet)
}

// jwks returns the signing key(s) the client can use to validate signatures
// from the authorization server.
//
// https://tools.ietf.org/html/rfc8414
func (a *Authenticate) jwks(w http.ResponseWriter, r *http.Request) error {
	httputil.RenderJSON(w, http.StatusOK, a.state.Load().jwk)
	return nil
}

// RetrieveSession is the middleware used retrieve session by the sessionLoaders
func (a *Authenticate) RetrieveSession(next http.Handler) http.Handler {
	return sessions.RetrieveSession(a.state.Load().sessionLoaders...)(next)
}

// VerifySession is the middleware used to enforce a valid authentication
// session state is attached to the users's request context.
func (a *Authenticate) VerifySession(next http.Handler) http.Handler {
	return httputil.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := trace.StartSpan(r.Context(), "authenticate.VerifySession")
		defer span.End()

		state := a.state.Load()
		options := a.options.Load()
		idp, err := options.GetIdentityProviderForID(r.FormValue(urlutil.QueryIdentityProviderID))
		if err != nil {
			return err
		}

		sessionState, err := a.getSessionFromCtx(ctx)
		if err != nil {
			log.FromRequest(r).Info().
				Err(err).
				Str("idp_id", idp.GetId()).
				Msg("authenticate: session load error")
			return a.reauthenticateOrFail(w, r, err)
		}

		if sessionState.IdentityProviderID != idp.GetId() {
			log.FromRequest(r).Info().
				Str("idp_id", idp.GetId()).
				Str("session_idp_id", sessionState.IdentityProviderID).
				Str("id", sessionState.ID).
				Msg("authenticate: session not associated with identity provider")
			return a.reauthenticateOrFail(w, r, err)
		}

		if state.dataBrokerClient == nil {
			return errors.New("authenticate: databroker client cannot be nil")
		}
		if _, err = session.Get(ctx, state.dataBrokerClient, sessionState.ID); err != nil {
			log.FromRequest(r).Info().
				Err(err).
				Str("idp_id", idp.GetId()).
				Str("id", sessionState.ID).
				Msg("authenticate: session not found in databroker")
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
	options := a.options.Load()
	idp, err := options.GetIdentityProviderForID(r.FormValue(urlutil.QueryIdentityProviderID))
	if err != nil {
		return err
	}

	redirectURL, err := urlutil.ParseAndValidateURL(r.FormValue(urlutil.QueryRedirectURI))
	if err != nil {
		return httputil.NewError(http.StatusBadRequest, err)
	}

	jwtAudience := []string{state.redirectURL.Host, redirectURL.Host}

	// if the callback is explicitly set, set it and add an additional audience
	if callbackStr := r.FormValue(urlutil.QueryCallbackURI); callbackStr != "" {
		callbackURL, err := urlutil.ParseAndValidateURL(callbackStr)
		if err != nil {
			return httputil.NewError(http.StatusBadRequest, err)
		}
		jwtAudience = append(jwtAudience, callbackURL.Host)
	}

	// add an additional claim for the forward-auth host, if set
	if fwdAuth := r.FormValue(urlutil.QueryForwardAuth); fwdAuth != "" {
		jwtAudience = append(jwtAudience, fwdAuth)
	}

	s, err := a.getSessionFromCtx(ctx)
	if err != nil {
		state.sessionStore.ClearSession(w, r)
		return err
	}

	// start over if this is a different identity provider
	if s == nil || s.IdentityProviderID != idp.GetId() {
		s = sessions.NewState(idp.GetId())
	}

	newSession := s.WithNewIssuer(state.redirectURL.Host, jwtAudience)

	// re-persist the session, useful when session was evicted from session
	if err := state.sessionStore.SaveSession(w, r, s); err != nil {
		return httputil.NewError(http.StatusBadRequest, err)
	}

	// sign the route session, as a JWT
	signedJWT, err := state.sharedEncoder.Marshal(newSession)
	if err != nil {
		return httputil.NewError(http.StatusBadRequest, err)
	}

	// encrypt our route-scoped JWT to avoid accidental logging of queryparams
	encryptedJWT := cryptutil.Encrypt(a.state.Load().sharedCipher, signedJWT, nil)
	// base64 our encrypted payload for URL-friendlyness
	encodedJWT := base64.URLEncoding.EncodeToString(encryptedJWT)

	callbackURL, err := urlutil.GetCallbackURL(r, encodedJWT)
	if err != nil {
		return httputil.NewError(http.StatusBadRequest, err)
	}

	// build our hmac-d redirect URL with our session, pointing back to the
	// proxy's callback URL which is responsible for setting our new route-session
	uri := urlutil.NewSignedURL(state.sharedKey, callbackURL)
	httputil.Redirect(w, r, uri.String(), http.StatusFound)
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
	idp, err := options.GetIdentityProviderForID(r.FormValue(urlutil.QueryIdentityProviderID))
	if err != nil {
		return err
	}

	authenticator, err := a.cfg.getIdentityProvider(options, idp.GetId())
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
	idp, err := options.GetIdentityProviderForID(r.FormValue(urlutil.QueryIdentityProviderID))
	if err != nil {
		return err
	}

	authenticator, err := a.cfg.getIdentityProvider(options, idp.GetId())
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

	// verify that the returned timestamp is valid
	if err := cryptutil.ValidTimestamp(statePayload[1]); err != nil {
		return nil, httputil.NewError(http.StatusBadRequest, err)
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

	idp, err := options.GetIdentityProviderForID(redirectURL.Query().Get(urlutil.QueryIdentityProviderID))
	if err != nil {
		return nil, err
	}

	authenticator, err := a.cfg.getIdentityProvider(options, idp.GetId())
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

	s := sessions.NewState(idp.GetId())
	err = claims.Claims.Claims(&s)
	if err != nil {
		return nil, fmt.Errorf("error unmarshaling session state: %w", err)
	}

	newState := s.WithNewIssuer(state.redirectURL.Hostname(), []string{state.redirectURL.Hostname()})
	if nextRedirectURL, err := urlutil.ParseAndValidateURL(redirectURL.Query().Get(urlutil.QueryRedirectURI)); err == nil {
		newState.Audience = append(newState.Audience, nextRedirectURL.Hostname())
	}

	// save the session and access token to the databroker
	err = a.saveSessionToDataBroker(ctx, r, &newState, claims, accessToken)
	if err != nil {
		return nil, httputil.NewError(http.StatusInternalServerError, err)
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

	authenticateURL, err := a.options.Load().GetAuthenticateURL()
	if err != nil {
		return handlers.UserInfoData{}, err
	}

	s, err := a.getSessionFromCtx(r.Context())
	if err != nil {
		s.ID = uuid.New().String()
	}

	pbSession, isImpersonated, err := a.getCurrentSession(r.Context())
	if err != nil {
		pbSession = &session.Session{
			Id: s.ID,
		}
	}

	pbUser, err := a.getUser(r.Context(), pbSession.GetUserId())
	if err != nil {
		pbUser = &user.User{
			Id: pbSession.GetUserId(),
		}
	}
	pbDirectoryUser, err := a.getDirectoryUser(r.Context(), pbSession.GetUserId())
	if err != nil {
		pbDirectoryUser = &directory.User{
			Id: pbSession.GetUserId(),
		}
	}
	var groups []*directory.Group
	for _, groupID := range pbDirectoryUser.GetGroupIds() {
		pbDirectoryGroup, err := directory.GetGroup(r.Context(), state.dataBrokerClient, groupID)
		if err != nil {
			pbDirectoryGroup = &directory.Group{
				Id:    groupID,
				Name:  groupID,
				Email: groupID,
			}
		}
		groups = append(groups, pbDirectoryGroup)
	}

	creationOptions, requestOptions, _ := a.webauthn.GetOptions(r.Context())

	return handlers.UserInfoData{
		CSRFToken:       csrf.Token(r),
		DirectoryGroups: groups,
		DirectoryUser:   pbDirectoryUser,
		IsImpersonated:  isImpersonated,
		Session:         pbSession,
		User:            pbUser,

		WebAuthnCreationOptions: creationOptions,
		WebAuthnRequestOptions:  requestOptions,
		WebAuthnURL:             urlutil.WebAuthnURL(r, authenticateURL, state.sharedKey, r.URL.Query()),

		BrandingOptions: a.options.Load().BrandingOptions,
	}, nil
}

func (a *Authenticate) saveSessionToDataBroker(
	ctx context.Context,
	r *http.Request,
	sessionState *sessions.State,
	claims identity.SessionClaims,
	accessToken *oauth2.Token,
) error {
	state := a.state.Load()
	options := a.options.Load()
	idp, err := options.GetIdentityProviderForID(r.FormValue(urlutil.QueryIdentityProviderID))
	if err != nil {
		return err
	}

	authenticator, err := a.cfg.getIdentityProvider(options, idp.GetId())
	if err != nil {
		return err
	}

	sessionExpiry := timestamppb.New(time.Now().Add(options.CookieExpire))
	idTokenIssuedAt := timestamppb.New(sessionState.IssuedAt.Time())

	s := &session.Session{
		Id:         sessionState.ID,
		UserId:     sessionState.UserID(authenticator.Name()),
		IssuedAt:   timestamppb.Now(),
		AccessedAt: timestamppb.Now(),
		ExpiresAt:  sessionExpiry,
		IdToken: &session.IDToken{
			Issuer:    sessionState.Issuer, // todo(bdd): the issuer is not authN but the downstream IdP from the claims
			Subject:   sessionState.Subject,
			ExpiresAt: sessionExpiry,
			IssuedAt:  idTokenIssuedAt,
		},
		OauthToken: manager.ToOAuthToken(accessToken),
		Audience:   sessionState.Audience,
	}
	s.SetRawIDToken(claims.RawIDToken)
	s.AddClaims(claims.Flatten())

	var managerUser manager.User
	managerUser.User, _ = user.Get(ctx, state.dataBrokerClient, s.GetUserId())
	if managerUser.User == nil {
		// if no user exists yet, create a new one
		managerUser.User = &user.User{
			Id: s.GetUserId(),
		}
	}
	err = authenticator.UpdateUserInfo(ctx, accessToken, &managerUser)
	if err != nil {
		return fmt.Errorf("authenticate: error retrieving user info: %w", err)
	}
	_, err = databroker.Put(ctx, state.dataBrokerClient, managerUser.User)
	if err != nil {
		return fmt.Errorf("authenticate: error saving user: %w", err)
	}

	res, err := session.Put(ctx, state.dataBrokerClient, s)
	if err != nil {
		return fmt.Errorf("authenticate: error saving session: %w", err)
	}
	sessionState.DatabrokerServerVersion = res.GetServerVersion()
	sessionState.DatabrokerRecordVersion = res.GetRecord().GetVersion()

	_, err = state.directoryClient.RefreshUser(ctx, &directory.RefreshUserRequest{
		UserId:      s.UserId,
		AccessToken: accessToken.AccessToken,
	})
	if err != nil {
		log.Error(ctx).Err(err).Msg("directory: failed to refresh user data")
	}

	return nil
}

// revokeSession always clears the local session and tries to revoke the associated session stored in the
// databroker. If successful, it returns the original `id_token` of the session, if failed, returns
// and empty string.
func (a *Authenticate) revokeSession(ctx context.Context, w http.ResponseWriter, r *http.Request) string {
	state := a.state.Load()
	options := a.options.Load()

	// clear the user's local session no matter what
	defer state.sessionStore.ClearSession(w, r)

	idp, err := options.GetIdentityProviderForID(r.FormValue(urlutil.QueryIdentityProviderID))
	if err != nil {
		return ""
	}

	authenticator, err := a.cfg.getIdentityProvider(options, idp.GetId())
	if err != nil {
		return ""
	}

	var rawIDToken string
	sessionState, err := a.getSessionFromCtx(ctx)
	if err != nil {
		return rawIDToken
	}

	if s, _ := session.Get(ctx, state.dataBrokerClient, sessionState.ID); s != nil && s.OauthToken != nil {
		rawIDToken = s.GetIdToken().GetRaw()
		if err := authenticator.Revoke(ctx, manager.FromOAuthToken(s.OauthToken)); err != nil {
			log.Ctx(ctx).Warn().Err(err).Msg("authenticate: failed to revoke access token")
		}
	}
	if err := session.Delete(ctx, state.dataBrokerClient, sessionState.ID); err != nil {
		log.Ctx(ctx).Warn().Err(err).Msg("authenticate: failed to delete session from session store")
	}

	return rawIDToken
}

func (a *Authenticate) getCurrentSession(ctx context.Context) (s *session.Session, isImpersonated bool, err error) {
	client := a.state.Load().dataBrokerClient

	sessionState, err := a.getSessionFromCtx(ctx)
	if err != nil {
		return nil, false, err
	}

	isImpersonated = false
	s, err = session.Get(ctx, client, sessionState.ID)
	if s.GetImpersonateSessionId() != "" {
		s, err = session.Get(ctx, client, s.GetImpersonateSessionId())
		isImpersonated = true
	}

	return s, isImpersonated, err
}

func (a *Authenticate) getUser(ctx context.Context, userID string) (*user.User, error) {
	client := a.state.Load().dataBrokerClient
	return user.Get(ctx, client, userID)
}

func (a *Authenticate) getDirectoryUser(ctx context.Context, userID string) (*directory.User, error) {
	client := a.state.Load().dataBrokerClient
	return directory.GetUser(ctx, client, userID)
}

func (a *Authenticate) getWebauthnState(ctx context.Context) (*webauthn.State, error) {
	state := a.state.Load()

	s, _, err := a.getCurrentSession(ctx)
	if err != nil {
		return nil, err
	}

	ss, err := a.getSessionFromCtx(ctx)
	if err != nil {
		return nil, err
	}

	authenticateURL, err := a.options.Load().GetAuthenticateURL()
	if err != nil {
		return nil, err
	}

	internalAuthenticateURL, err := a.options.Load().GetInternalAuthenticateURL()
	if err != nil {
		return nil, err
	}

	pomeriumDomains, err := a.options.Load().GetAllRouteableHTTPDomains()
	if err != nil {
		return nil, err
	}

	return &webauthn.State{
		AuthenticateURL:         authenticateURL,
		InternalAuthenticateURL: internalAuthenticateURL,
		SharedKey:               state.sharedKey,
		Client:                  state.dataBrokerClient,
		PomeriumDomains:         pomeriumDomains,
		Session:                 s,
		SessionState:            ss,
		SessionStore:            state.sessionStore,
		RelyingParty:            state.webauthnRelyingParty,
		BrandingOptions:         a.options.Load().BrandingOptions,
	}, nil
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
