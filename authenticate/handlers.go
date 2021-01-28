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

	"github.com/golang/protobuf/ptypes"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/rs/cors"
	"golang.org/x/oauth2"
	"gopkg.in/square/go-jose.v2/jwt"

	"github.com/pomerium/csrf"

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
		return csrf.Protect(
			state.cookieSecret,
			csrf.Secure(options.CookieSecure),
			csrf.Path("/"),
			csrf.UnsafePaths([]string{state.redirectURL.Path}), // enforce CSRF on "safe" handler
			csrf.FormValueName("state"),                        // rfc6749 section-10.12
			csrf.CookieName(fmt.Sprintf("%s_csrf", options.CookieName)),
			csrf.ErrorHandler(httputil.HandlerFunc(httputil.CSRFFailureHandler)),
		)(h)
	})

	r.Path("/robots.txt").HandlerFunc(a.RobotsTxt).Methods(http.MethodGet)
	// Identity Provider (IdP) endpoints
	r.Path("/oauth2/callback").Handler(httputil.HandlerFunc(a.OAuthCallback)).Methods(http.MethodGet)

	// Proxy service endpoints
	s := r.PathPrefix("/.pomerium/frontchannel-logout").Subrouter()
	s.Use(a.RetrieveSession)
	s.Path("/").Handler(httputil.HandlerFunc(a.FrontchannelLogout)).Methods(http.MethodGet)

	v := r.PathPrefix("/.pomerium").Subrouter()
	c := cors.New(cors.Options{
		AllowOriginRequestFunc: func(r *http.Request, _ string) bool {
			state := a.state.Load()
			err := middleware.ValidateRequestURL(r, string(state.sharedSecret))
			if err != nil {
				log.FromRequest(r).Info().Err(err).Msg("authenticate: origin blocked")
			}
			return err == nil
		},
		AllowCredentials: true,
		AllowedHeaders:   []string{"*"},
	})
	v.Use(c.Handler)
	v.Use(a.RetrieveSession)
	v.Use(a.VerifySession)
	v.Path("/").Handler(httputil.HandlerFunc(a.userInfo))
	v.Path("/sign_in").Handler(httputil.HandlerFunc(a.SignIn))
	v.Path("/sign_out").Handler(httputil.HandlerFunc(a.SignOut))

	wk := r.PathPrefix("/.well-known/pomerium").Subrouter()
	wk.Path("/jwks.json").Handler(httputil.HandlerFunc(a.jwks)).Methods(http.MethodGet)
	wk.Path("/").Handler(httputil.HandlerFunc(a.wellKnown)).Methods(http.MethodGet)
}

// Well-Known Uniform Resource Identifiers (URIs)
// https://en.wikipedia.org/wiki/List_of_/.well-known/_services_offered_by_webservers
func (a *Authenticate) wellKnown(w http.ResponseWriter, r *http.Request) error {
	state := a.state.Load()

	wellKnownURLS := struct {
		// URL string referencing the client's JSON Web Key (JWK) Set
		// RFC7517 document, which contains the client's public keys.
		JSONWebKeySetURL      string `json:"jwks_uri"`
		OAuth2Callback        string `json:"authentication_callback_endpoint"`
		FrontchannelLogoutURI string `json:"frontchannel_logout_uri"`
	}{
		state.redirectURL.ResolveReference(&url.URL{Path: "/.well-known/pomerium/jwks.json"}).String(),
		state.redirectURL.ResolveReference(&url.URL{Path: "/oauth2/callback"}).String(),
		state.redirectURL.ResolveReference(&url.URL{Path: "/.pomerium/frontchannel-logout"}).String(),
	}
	httputil.RenderJSON(w, http.StatusOK, wellKnownURLS)
	return nil
}

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

		sessionState, err := a.getSessionFromCtx(ctx)
		if err != nil {
			log.FromRequest(r).Info().Err(err).Msg("authenticate: session load error")
			return a.reauthenticateOrFail(w, r, err)
		}

		if state.dataBrokerClient == nil {
			return errors.New("authenticate: databroker client cannot be nil")
		}
		if _, err = session.Get(ctx, state.dataBrokerClient, sessionState.ID); err != nil {
			log.FromRequest(r).Info().Err(err).Str("id", sessionState.ID).Msg("authenticate: session not found in databroker")
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

	options := a.options.Load()
	state := a.state.Load()

	redirectURL, err := urlutil.ParseAndValidateURL(r.FormValue(urlutil.QueryRedirectURI))
	if err != nil {
		return httputil.NewError(http.StatusBadRequest, err)
	}

	jwtAudience := []string{state.redirectURL.Host, redirectURL.Host}

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
		state.sessionStore.ClearSession(w, r)
		return err
	}

	newSession := sessions.NewSession(s, state.redirectURL.Host, jwtAudience)

	// re-persist the session, useful when session was evicted from session
	if err := state.sessionStore.SaveSession(w, r, s); err != nil {
		return httputil.NewError(http.StatusBadRequest, err)
	}

	callbackParams := callbackURL.Query()

	if r.FormValue(urlutil.QueryIsProgrammatic) == "true" {
		newSession.Programmatic = true
		callbackParams.Set(urlutil.QueryIsProgrammatic, "true")
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

	// add our encoded and encrypted route-session JWT to a query param
	callbackParams.Set(urlutil.QuerySessionEncrypted, encodedJWT)
	callbackParams.Set(urlutil.QueryRedirectURI, redirectURL.String())
	callbackURL.RawQuery = callbackParams.Encode()

	// build our hmac-d redirect URL with our session, pointing back to the
	// proxy's callback URL which is responsible for setting our new route-session
	uri := urlutil.NewSignedURL(options.SharedKey, callbackURL)
	httputil.Redirect(w, r, uri.String(), http.StatusFound)
	return nil
}

// SignOut signs the user out and attempts to revoke the user's identity session
// Handles both GET and POST.
func (a *Authenticate) SignOut(w http.ResponseWriter, r *http.Request) error {
	ctx, span := trace.StartSpan(r.Context(), "authenticate.SignOut")
	defer span.End()

	rawIDToken := a.revokeSession(ctx, w, r)

	redirectString := ""
	if sru := a.options.Load().SignOutRedirectURL; sru != nil {
		redirectString = sru.String()
	}
	if uri := r.FormValue(urlutil.QueryRedirectURI); uri != "" {
		redirectString = uri
	}

	endSessionURL, err := a.provider.Load().LogOut()
	if err == nil && redirectString != "" {
		params := url.Values{}
		params.Add("id_token_hint", rawIDToken)
		params.Add("post_logout_redirect_uri", redirectString)
		endSessionURL.RawQuery = params.Encode()
		redirectString = endSessionURL.String()
	} else if !errors.Is(err, oidc.ErrSignoutNotImplemented) {
		log.Warn().Err(err).Msg("authenticate.SignOut: failed getting session")
	}

	httputil.Redirect(w, r, redirectString, http.StatusFound)

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
	state := a.state.Load()
	// If request AJAX/XHR request, return a 401 instead because the redirect
	// will almost certainly violate their CORs policy
	if reqType := r.Header.Get("X-Requested-With"); strings.EqualFold(reqType, "XmlHttpRequest") {
		return httputil.NewError(http.StatusUnauthorized, err)
	}
	state.sessionStore.ClearSession(w, r)
	redirectURL := state.redirectURL.ResolveReference(r.URL)
	nonce := csrf.Token(r)
	now := time.Now().Unix()
	b := []byte(fmt.Sprintf("%s|%d|", nonce, now))
	enc := cryptutil.Encrypt(state.cookieCipher, []byte(redirectURL.String()), b)
	b = append(b, enc...)
	encodedState := base64.URLEncoding.EncodeToString(b)
	signinURL, err := a.provider.Load().GetSignInURL(encodedState)
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
	var claims identity.SessionClaims
	accessToken, err := a.provider.Load().Authenticate(ctx, code, &claims)
	if err != nil {
		return nil, fmt.Errorf("error redeeming authenticate code: %w", err)
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

	s := sessions.State{ID: uuid.New().String()}
	err = claims.Claims.Claims(&s)
	if err != nil {
		return nil, fmt.Errorf("error unmarshaling session state: %w", err)
	}

	newState := sessions.NewSession(
		&s,
		state.redirectURL.Hostname(),
		[]string{state.redirectURL.Hostname()})

	if nextRedirectURL, err := urlutil.ParseAndValidateURL(redirectURL.Query().Get(urlutil.QueryRedirectURI)); err == nil {
		newState.Audience = append(newState.Audience, nextRedirectURL.Hostname())
	}

	// save the session and access token to the databroker
	err = a.saveSessionToDataBroker(ctx, &newState, claims, accessToken)
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

func (a *Authenticate) deleteSession(ctx context.Context, sessionID string) error {
	state := a.state.Load()
	return session.Delete(ctx, state.dataBrokerClient, sessionID)
}

func (a *Authenticate) userInfo(w http.ResponseWriter, r *http.Request) error {
	ctx, span := trace.StartSpan(r.Context(), "authenticate.userInfo")
	defer span.End()

	state := a.state.Load()

	s, err := a.getSessionFromCtx(ctx)
	if err != nil {
		s.ID = uuid.New().String()
	}

	pbSession, err := session.Get(ctx, state.dataBrokerClient, s.ID)
	if err != nil {
		pbSession = &session.Session{
			Id: s.ID,
		}
	}
	pbUser, err := user.Get(ctx, state.dataBrokerClient, pbSession.GetUserId())
	if err != nil {
		pbUser = &user.User{
			Id: pbSession.GetUserId(),
		}
	}
	pbDirectoryUser, err := directory.GetUser(ctx, state.dataBrokerClient, pbSession.GetUserId())
	if err != nil {
		pbDirectoryUser = &directory.User{
			Id: pbSession.GetUserId(),
		}
	}
	var groups []*directory.Group
	for _, groupID := range pbDirectoryUser.GetGroupIds() {
		pbDirectoryGroup, err := directory.GetGroup(ctx, state.dataBrokerClient, groupID)
		if err != nil {
			pbDirectoryGroup = &directory.Group{
				Id:    groupID,
				Name:  groupID,
				Email: groupID,
			}
		}
		groups = append(groups, pbDirectoryGroup)
	}
	input := map[string]interface{}{
		"State":           s,               // local session state (cookie, header, etc)
		"Session":         pbSession,       // current access, refresh, id token, & impersonation state
		"User":            pbUser,          // user details inferred from oidc id_token
		"DirectoryUser":   pbDirectoryUser, // user details inferred from idp directory
		"DirectoryGroups": groups,          // user's groups inferred from idp directory
		"csrfField":       csrf.TemplateField(r),
		"RedirectURL":     r.URL.Query().Get(urlutil.QueryRedirectURI),
	}

	if redirectURL, err := url.Parse(r.URL.Query().Get(urlutil.QueryRedirectURI)); err == nil {
		input["RedirectURL"] = redirectURL.String()
		signOutURL := redirectURL.ResolveReference(new(url.URL))
		signOutURL.Path = "/.pomerium/sign_out"
		input["SignOutURL"] = signOutURL.String()
	} else {
		input["SignOutURL"] = "/.pomerium/sign_out"
	}

	return a.templates.ExecuteTemplate(w, "userInfo.html", input)
}

func (a *Authenticate) saveSessionToDataBroker(
	ctx context.Context,
	sessionState *sessions.State,
	claims identity.SessionClaims,
	accessToken *oauth2.Token,
) error {
	state := a.state.Load()
	options := a.options.Load()

	sessionExpiry, _ := ptypes.TimestampProto(time.Now().Add(options.CookieExpire))
	sessionState.Expiry = jwt.NewNumericDate(sessionExpiry.AsTime())
	idTokenIssuedAt, _ := ptypes.TimestampProto(sessionState.IssuedAt.Time())

	s := &session.Session{
		Id:        sessionState.ID,
		UserId:    sessionState.UserID(a.provider.Load().Name()),
		ExpiresAt: sessionExpiry,
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

	// if no user exists yet, create a new one
	currentUser, _ := user.Get(ctx, state.dataBrokerClient, s.GetUserId())
	if currentUser == nil {
		mu := manager.User{
			User: &user.User{
				Id: s.GetUserId(),
			},
		}
		err := a.provider.Load().UpdateUserInfo(ctx, accessToken, &mu)
		if err != nil {
			return fmt.Errorf("authenticate: error retrieving user info: %w", err)
		}
		_, err = user.Set(ctx, state.dataBrokerClient, mu.User)
		if err != nil {
			return fmt.Errorf("authenticate: error saving user: %w", err)
		}
	}

	res, err := session.Set(ctx, state.dataBrokerClient, s)
	if err != nil {
		return fmt.Errorf("authenticate: error saving session: %w", err)
	}
	sessionState.Version = sessions.Version(res.GetServerVersion())

	_, err = state.directoryClient.RefreshUser(ctx, &directory.RefreshUserRequest{
		UserId:      s.UserId,
		AccessToken: accessToken.AccessToken,
	})
	if err != nil {
		log.Error().Err(err).Msg("directory: failed to refresh user data")
	}

	return nil
}

// FrontchannelLogout uses HTTP GETs to Relying Party URLs (Pomerium) to clear a user's login state.
// This endpoint implements OpenID Connect Front-Channel Logout and reuses the Relying
// Party-initiated logout functionality specified in Section 5 of OpenID Connect Session Management
// 1.0 (RP-Initiated Logout).
//
// https://openid.net/specs/openid-connect-frontchannel-1_0.html
// https://ldapwiki.com/wiki/OpenID%20Connect%20Front-Channel%20Logout
func (a *Authenticate) FrontchannelLogout(w http.ResponseWriter, r *http.Request) error {
	ctx, span := trace.StartSpan(r.Context(), "authenticate.FrontchannelLogout")
	defer span.End()

	_ = a.revokeSession(ctx, w, r)

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, http.StatusText(http.StatusOK))
	return nil
}

// revokeSession always clears the local session and tries to revoke the associated session stored in the
// databroker. If successful, it returns the original `id_token` of the session, if failed, returns
// and empty string.
func (a *Authenticate) revokeSession(ctx context.Context, w http.ResponseWriter, r *http.Request) string {
	state := a.state.Load()
	// clear the user's local session no matter what
	defer state.sessionStore.ClearSession(w, r)

	var rawIDToken string
	sessionState, err := a.getSessionFromCtx(ctx)
	if err != nil {
		return rawIDToken
	}

	if s, _ := session.Get(ctx, state.dataBrokerClient, sessionState.ID); s != nil && s.OauthToken != nil {
		rawIDToken = s.GetIdToken().GetRaw()
		if err := a.provider.Load().Revoke(ctx, manager.FromOAuthToken(s.OauthToken)); err != nil {
			log.Ctx(ctx).Warn().Err(err).Msg("authenticate: failed to revoke access token")
		}
	}
	if err := a.deleteSession(ctx, sessionState.ID); err != nil {
		log.Ctx(ctx).Warn().Err(err).Msg("authenticate: failed to delete session from session store")
	}

	return rawIDToken
}
