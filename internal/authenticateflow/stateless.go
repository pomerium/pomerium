package authenticateflow

import (
	"context"
	"crypto/cipher"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/go-jose/go-jose/v3"
	"golang.org/x/oauth2"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/pomerium/pomerium/authenticate/events"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/encoding"
	"github.com/pomerium/pomerium/internal/encoding/jws"
	"github.com/pomerium/pomerium/internal/handlers"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	"github.com/pomerium/pomerium/pkg/grpc"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	identitypb "github.com/pomerium/pomerium/pkg/grpc/identity"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpc/user"
	"github.com/pomerium/pomerium/pkg/hpke"
	"github.com/pomerium/pomerium/pkg/identity"
)

// Stateless implements the stateless authentication flow. In this flow, the
// authenticate service has no direct access to the databroker and instead
// stores profile information in a cookie.
type Stateless struct {
	signatureVerifier

	// sharedEncoder is the encoder to use to serialize data to be consumed
	// by other services
	sharedEncoder encoding.MarshalUnmarshaler
	// cookieCipher is the cipher to use to encrypt/decrypt session data
	cookieCipher cipher.AEAD

	sessionStore sessions.SessionStore

	hpkePrivateKey         *hpke.PrivateKey
	authenticateKeyFetcher hpke.KeyFetcher

	jwk *jose.JSONWebKeySet

	authenticateURL *url.URL

	options *config.Options

	dataBrokerClient databroker.DataBrokerServiceClient

	getIdentityProvider func(options *config.Options, idpID string) (identity.Authenticator, error)
	profileTrimFn       func(*identitypb.Profile)
	authEventFn         events.AuthEventFn
}

// NewStateless initializes the authentication flow for the given
// configuration, session store, and additional options.
func NewStateless(
	ctx context.Context,
	cfg *config.Config,
	sessionStore sessions.SessionStore,
	getIdentityProvider func(options *config.Options, idpID string) (identity.Authenticator, error),
	profileTrimFn func(*identitypb.Profile),
	authEventFn events.AuthEventFn,
) (*Stateless, error) {
	s := &Stateless{
		options:             cfg.Options,
		sessionStore:        sessionStore,
		getIdentityProvider: getIdentityProvider,
		profileTrimFn:       profileTrimFn,
		authEventFn:         authEventFn,
	}

	var err error
	s.authenticateURL, err = cfg.Options.GetAuthenticateURL()
	if err != nil {
		return nil, err
	}

	// shared cipher to encrypt data before passing data between services
	sharedKey, err := cfg.Options.GetSharedKey()
	if err != nil {
		return nil, err
	}

	// shared state encoder setup
	s.sharedEncoder, err = jws.NewHS256Signer(sharedKey)
	if err != nil {
		return nil, err
	}

	// private state encoder setup, used to encrypt oauth2 tokens
	cookieSecret, err := cfg.Options.GetCookieSecret()
	if err != nil {
		return nil, err
	}

	s.cookieCipher, err = cryptutil.NewAEADCipher(cookieSecret)
	if err != nil {
		return nil, err
	}

	s.jwk = new(jose.JSONWebKeySet)
	signingKey, err := cfg.Options.GetSigningKey()
	if err != nil {
		return nil, err
	}
	if len(signingKey) > 0 {
		ks, err := cryptutil.PublicJWKsFromBytes(signingKey)
		if err != nil {
			return nil, fmt.Errorf("authenticate: failed to convert jwks: %w", err)
		}
		for _, k := range ks {
			s.jwk.Keys = append(s.jwk.Keys, *k)
		}
	}

	s.signatureVerifier = signatureVerifier{cfg.Options, sharedKey}

	s.hpkePrivateKey = hpke.DerivePrivateKey(sharedKey)

	s.authenticateKeyFetcher, err = cfg.GetAuthenticateKeyFetcher()
	if err != nil {
		return nil, fmt.Errorf("authorize: get authenticate JWKS key fetcher: %w", err)
	}

	dataBrokerConn, err := outboundGRPCConnection.Get(ctx, &grpc.OutboundOptions{
		OutboundPort:   cfg.OutboundPort,
		InstallationID: cfg.Options.InstallationID,
		ServiceName:    cfg.Options.Services,
		SignedJWTKey:   sharedKey,
	})
	if err != nil {
		return nil, err
	}

	s.dataBrokerClient = databroker.NewDataBrokerServiceClient(dataBrokerConn)

	return s, nil
}

// VerifySession checks that an existing session is still valid.
func (s *Stateless) VerifySession(ctx context.Context, r *http.Request, _ *sessions.State) error {
	profile, err := loadIdentityProfile(r, s.cookieCipher)
	if err != nil {
		return fmt.Errorf("identity profile load error: %w", err)
	}

	authenticator, err := s.getIdentityProvider(s.options, profile.GetProviderId())
	if err != nil {
		return fmt.Errorf("couldn't get identity provider: %w", err)
	}

	if err := validateIdentityProfile(ctx, authenticator, profile); err != nil {
		return fmt.Errorf("invalid identity profile: %w", err)
	}

	return nil
}

// SignIn redirects to a route callback URL, if the provided request and
// session state are valid.
func (s *Stateless) SignIn(
	w http.ResponseWriter,
	r *http.Request,
	sessionState *sessions.State,
) error {
	if err := r.ParseForm(); err != nil {
		return httputil.NewError(http.StatusBadRequest, err)
	}
	proxyPublicKey, requestParams, err := hpke.DecryptURLValues(s.hpkePrivateKey, r.Form)
	if err != nil {
		return err
	}

	idpID := requestParams.Get(urlutil.QueryIdentityProviderID)

	// start over if this is a different identity provider
	if sessionState == nil || sessionState.IdentityProviderID != idpID {
		sessionState = sessions.NewState(idpID)
	}

	// re-persist the session, useful when session was evicted from session store
	if err := s.sessionStore.SaveSession(w, r, sessionState); err != nil {
		return httputil.NewError(http.StatusBadRequest, err)
	}

	profile, err := loadIdentityProfile(r, s.cookieCipher)
	if err != nil {
		return httputil.NewError(http.StatusBadRequest, err)
	}

	if s.profileTrimFn != nil {
		s.profileTrimFn(profile)
	}

	s.logAuthenticateEvent(r, profile)

	encryptURLValues := hpke.EncryptURLValuesV1
	if hpke.IsEncryptedURLV2(r.Form) {
		encryptURLValues = hpke.EncryptURLValuesV2
	}

	redirectTo, err := urlutil.CallbackURL(s.hpkePrivateKey, proxyPublicKey, requestParams, profile, encryptURLValues)
	if err != nil {
		return httputil.NewError(http.StatusInternalServerError, err)
	}

	httputil.Redirect(w, r, redirectTo, http.StatusFound)
	return nil
}

// PersistSession stores session data in a cookie.
func (s *Stateless) PersistSession(
	ctx context.Context,
	w http.ResponseWriter,
	sessionState *sessions.State,
	claims identity.SessionClaims,
	accessToken *oauth2.Token,
) error {
	idpID := sessionState.IdentityProviderID
	profile, err := buildIdentityProfile(idpID, claims, accessToken)
	if err != nil {
		return err
	}
	err = storeIdentityProfile(w, s.options.NewCookie(), s.cookieCipher, profile)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("failed to store identity profile")
	}
	return nil
}

// GetUserInfoData returns user info data associated with the given request (if
// any).
func (s *Stateless) GetUserInfoData(r *http.Request, _ *sessions.State) handlers.UserInfoData {
	profile, _ := loadIdentityProfile(r, s.cookieCipher)
	return handlers.UserInfoData{
		Profile: profile,
	}
}

// RevokeSession revokes the session associated with the provided request,
// returning the ID token from the revoked session.
func (s *Stateless) RevokeSession(
	ctx context.Context, r *http.Request, authenticator identity.Authenticator, _ *sessions.State,
) string {
	profile, err := loadIdentityProfile(r, s.cookieCipher)
	if err != nil {
		return ""
	}

	oauthToken := new(oauth2.Token)
	_ = json.Unmarshal(profile.GetOauthToken(), oauthToken)
	if err := authenticator.Revoke(ctx, oauthToken); err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("authenticate: failed to revoke access token")
	}

	return string(profile.GetIdToken())
}

// GetIdentityProviderIDForURLValues returns the identity provider ID
// associated with the given URL values.
func (s *Stateless) GetIdentityProviderIDForURLValues(vs url.Values) string {
	idpID := ""
	if _, requestParams, err := hpke.DecryptURLValues(s.hpkePrivateKey, vs); err == nil {
		if idpID == "" {
			idpID = requestParams.Get(urlutil.QueryIdentityProviderID)
		}
	}
	if idpID == "" {
		idpID = vs.Get(urlutil.QueryIdentityProviderID)
	}
	return idpID
}

// LogAuthenticateEvent logs an authenticate service event.
func (s *Stateless) LogAuthenticateEvent(r *http.Request) {
	s.logAuthenticateEvent(r, nil)
}

func (s *Stateless) logAuthenticateEvent(r *http.Request, profile *identitypb.Profile) {
	if s.authEventFn == nil {
		return
	}

	ctx := r.Context()
	pub, params, err := hpke.DecryptURLValues(s.hpkePrivateKey, r.Form)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("log authenticate event: failed to decrypt request params")
	}

	evt := events.AuthEvent{
		IP:          httputil.GetClientIP(r),
		Version:     params.Get(urlutil.QueryVersion),
		RequestUUID: params.Get(urlutil.QueryRequestUUID),
		PubKey:      pub.String(),
	}

	if uid := getUserClaim(profile, "sub"); uid != nil {
		evt.UID = uid
	}
	if email := getUserClaim(profile, "email"); email != nil {
		evt.Email = email
	}

	if evt.UID != nil {
		evt.Event = events.AuthEventSignInComplete
	} else {
		evt.Event = events.AuthEventSignInRequest
	}

	if redirectURL, err := url.Parse(params.Get(urlutil.QueryRedirectURI)); err == nil {
		domain := redirectURL.Hostname()
		evt.Domain = &domain
	}

	s.authEventFn(ctx, evt)
}

func getUserClaim(profile *identitypb.Profile, field string) *string {
	if profile == nil {
		return nil
	}
	if profile.Claims == nil {
		return nil
	}
	val, ok := profile.Claims.Fields[field]
	if !ok || val == nil {
		return nil
	}
	txt := val.GetStringValue()
	return &txt
}

// AuthenticateSignInURL returns a URL to redirect the user to the authenticate
// domain.
func (s *Stateless) AuthenticateSignInURL(
	ctx context.Context, queryParams url.Values, redirectURL *url.URL, idpID string,
) (string, error) {
	authenticateHPKEPublicKey, err := s.authenticateKeyFetcher.FetchPublicKey(ctx)
	if err != nil {
		return "", err
	}

	authenticateURLWithParams := *s.authenticateURL
	q := authenticateURLWithParams.Query()
	for k, v := range queryParams {
		q[k] = v
	}
	authenticateURLWithParams.RawQuery = q.Encode()

	return urlutil.SignInURL(
		s.hpkePrivateKey,
		authenticateHPKEPublicKey,
		&authenticateURLWithParams,
		redirectURL,
		idpID,
	)
}

// Callback handles a redirect to a route domain once signed in.
func (s *Stateless) Callback(w http.ResponseWriter, r *http.Request) error {
	if err := r.ParseForm(); err != nil {
		return httputil.NewError(http.StatusBadRequest, err)
	}

	// decrypt the URL values
	senderPublicKey, values, err := hpke.DecryptURLValues(s.hpkePrivateKey, r.Form)
	if err != nil {
		return httputil.NewError(http.StatusBadRequest, fmt.Errorf("invalid encrypted query string: %w", err))
	}

	// confirm this request came from the authenticate service
	err = s.validateSenderPublicKey(r.Context(), senderPublicKey)
	if err != nil {
		return err
	}

	// validate that the request has not expired
	err = urlutil.ValidateTimeParameters(values)
	if err != nil {
		return httputil.NewError(http.StatusBadRequest, err)
	}

	profile, err := getProfileFromValues(values)
	if err != nil {
		return err
	}

	ss := newSessionStateFromProfile(profile)
	sess, err := session.Get(r.Context(), s.dataBrokerClient, ss.ID)
	if err != nil {
		sess = &session.Session{Id: ss.ID}
	}
	populateSessionFromProfile(sess, profile, ss, s.options.CookieExpire)
	u, err := user.Get(r.Context(), s.dataBrokerClient, ss.UserID())
	if err != nil {
		u = &user.User{Id: ss.UserID()}
	}
	populateUserFromClaims(u, profile.GetClaims().AsMap())

	redirectURI, err := getRedirectURIFromValues(values)
	if err != nil {
		return err
	}

	// save the records
	res, err := s.dataBrokerClient.Put(r.Context(), &databroker.PutRequest{
		Records: []*databroker.Record{
			databroker.NewRecord(sess),
			databroker.NewRecord(u),
		},
	})
	if err != nil {
		return httputil.NewError(http.StatusInternalServerError, fmt.Errorf("proxy: error saving databroker records: %w", err))
	}
	ss.DatabrokerServerVersion = res.GetServerVersion()
	for _, record := range res.GetRecords() {
		if record.GetVersion() > ss.DatabrokerRecordVersion {
			ss.DatabrokerRecordVersion = record.GetVersion()
		}
	}

	// save the session state
	rawJWT, err := s.sharedEncoder.Marshal(ss)
	if err != nil {
		return httputil.NewError(http.StatusInternalServerError, fmt.Errorf("proxy: error marshaling session state: %w", err))
	}
	if err = s.sessionStore.SaveSession(w, r, rawJWT); err != nil {
		return httputil.NewError(http.StatusInternalServerError, fmt.Errorf("proxy: error saving session state: %w", err))
	}

	// if programmatic, encode the session jwt as a query param
	if isProgrammatic := values.Get(urlutil.QueryIsProgrammatic); isProgrammatic == "true" {
		q := redirectURI.Query()
		q.Set(urlutil.QueryPomeriumJWT, string(rawJWT))
		redirectURI.RawQuery = q.Encode()
	}

	// redirect
	httputil.Redirect(w, r, redirectURI.String(), http.StatusFound)
	return nil
}

func (s *Stateless) validateSenderPublicKey(ctx context.Context, senderPublicKey *hpke.PublicKey) error {
	authenticatePublicKey, err := s.authenticateKeyFetcher.FetchPublicKey(ctx)
	if err != nil {
		return httputil.NewError(http.StatusInternalServerError, fmt.Errorf("hpke: error retrieving authenticate service public key: %w", err))
	}

	if !authenticatePublicKey.Equals(senderPublicKey) {
		return httputil.NewError(http.StatusBadRequest, fmt.Errorf("hpke: invalid authenticate service public key"))
	}

	return nil
}

func getProfileFromValues(values url.Values) (*identitypb.Profile, error) {
	rawProfile := values.Get(urlutil.QueryIdentityProfile)
	if rawProfile == "" {
		return nil, httputil.NewError(http.StatusBadRequest, fmt.Errorf("missing %s", urlutil.QueryIdentityProfile))
	}

	var profile identitypb.Profile
	err := protojson.Unmarshal([]byte(rawProfile), &profile)
	if err != nil {
		return nil, httputil.NewError(http.StatusBadRequest, fmt.Errorf("invalid %s: %w", urlutil.QueryIdentityProfile, err))
	}
	return &profile, nil
}

func getRedirectURIFromValues(values url.Values) (*url.URL, error) {
	rawRedirectURI := values.Get(urlutil.QueryRedirectURI)
	if rawRedirectURI == "" {
		return nil, httputil.NewError(http.StatusBadRequest, fmt.Errorf("missing %s", urlutil.QueryRedirectURI))
	}
	redirectURI, err := urlutil.ParseAndValidateURL(rawRedirectURI)
	if err != nil {
		return nil, httputil.NewError(http.StatusBadRequest, fmt.Errorf("invalid %s: %w", urlutil.QueryRedirectURI, err))
	}
	return redirectURI, nil
}
