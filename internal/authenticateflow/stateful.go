package authenticateflow

import (
	"context"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/oauth2"
	"google.golang.org/protobuf/types/known/timestamppb"

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
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpc/user"
	"github.com/pomerium/pomerium/pkg/grpcutil"
	"github.com/pomerium/pomerium/pkg/identity"
	"github.com/pomerium/pomerium/pkg/identity/manager"
)

// Stateful implements the stateful authentication flow. In this flow, the
// authenticate service has direct access to the databroker.
type Stateful struct {
	signatureVerifier

	// sharedEncoder is the encoder to use to serialize data to be consumed
	// by other services
	sharedEncoder encoding.MarshalUnmarshaler
	// sharedKey is the secret to encrypt and authenticate data shared between services
	sharedKey []byte
	// sharedCipher is the cipher to use to encrypt/decrypt data shared between services
	sharedCipher cipher.AEAD
	// sessionDuration is the maximum Pomerium session duration
	sessionDuration time.Duration
	// sessionStore is the session store used to persist a user's session
	sessionStore sessions.SessionStore

	defaultIdentityProviderID string

	authenticateURL *url.URL

	dataBrokerClient databroker.DataBrokerServiceClient
}

// NewStateful initializes the authentication flow for the given configuration
// and session store.
func NewStateful(cfg *config.Config, sessionStore sessions.SessionStore) (*Stateful, error) {
	s := &Stateful{
		sessionDuration: cfg.Options.CookieExpire,
		sessionStore:    sessionStore,
	}

	var err error
	s.authenticateURL, err = cfg.Options.GetAuthenticateURL()
	if err != nil {
		return nil, err
	}
	// shared cipher to encrypt data before passing data between services
	s.sharedKey, err = cfg.Options.GetSharedKey()
	if err != nil {
		return nil, err
	}
	s.sharedCipher, err = cryptutil.NewAEADCipher(s.sharedKey)
	if err != nil {
		return nil, err
	}
	// shared state encoder setup
	s.sharedEncoder, err = jws.NewHS256Signer(s.sharedKey)
	if err != nil {
		return nil, err
	}
	s.signatureVerifier = signatureVerifier{cfg.Options, s.sharedKey}

	idp, err := cfg.Options.GetIdentityProviderForPolicy(nil)
	if err == nil {
		s.defaultIdentityProviderID = idp.GetId()
	}

	dataBrokerConn, err := outboundGRPCConnection.Get(context.Background(),
		&grpc.OutboundOptions{
			OutboundPort:   cfg.OutboundPort,
			InstallationID: cfg.Options.InstallationID,
			ServiceName:    cfg.Options.Services,
			SignedJWTKey:   s.sharedKey,
		})
	if err != nil {
		return nil, err
	}

	s.dataBrokerClient = databroker.NewDataBrokerServiceClient(dataBrokerConn)
	return s, nil
}

// SignIn redirects to a route callback URL, if the provided request and
// session state are valid.
func (s *Stateful) SignIn(
	w http.ResponseWriter,
	r *http.Request,
	sessionState *sessions.State,
) error {
	if err := s.VerifyAuthenticateSignature(r); err != nil {
		return httputil.NewError(http.StatusBadRequest, err)
	}

	idpID := r.FormValue(urlutil.QueryIdentityProviderID)

	// start over if this is a different identity provider
	if sessionState == nil || sessionState.IdentityProviderID != idpID {
		sessionState = sessions.NewState(idpID)
	}

	redirectURL, err := urlutil.ParseAndValidateURL(r.FormValue(urlutil.QueryRedirectURI))
	if err != nil {
		return httputil.NewError(http.StatusBadRequest, err)
	}

	jwtAudience := []string{s.authenticateURL.Host, redirectURL.Host}

	// if the callback is explicitly set, set it and add an additional audience
	if callbackStr := r.FormValue(urlutil.QueryCallbackURI); callbackStr != "" {
		callbackURL, err := urlutil.ParseAndValidateURL(callbackStr)
		if err != nil {
			return httputil.NewError(http.StatusBadRequest, err)
		}
		jwtAudience = append(jwtAudience, callbackURL.Host)
	}

	newSession := sessionState.WithNewIssuer(s.authenticateURL.Host, jwtAudience)

	// re-persist the session, useful when session was evicted from session store
	if err := s.sessionStore.SaveSession(w, r, sessionState); err != nil {
		return httputil.NewError(http.StatusBadRequest, err)
	}

	// sign the route session, as a JWT
	signedJWT, err := s.sharedEncoder.Marshal(newSession)
	if err != nil {
		return httputil.NewError(http.StatusBadRequest, err)
	}

	// encrypt our route-scoped JWT to avoid accidental logging of queryparams
	encryptedJWT := cryptutil.Encrypt(s.sharedCipher, signedJWT, nil)
	// base64 our encrypted payload for URL-friendlyness
	encodedJWT := base64.URLEncoding.EncodeToString(encryptedJWT)

	callbackURL, err := urlutil.GetCallbackURL(r, encodedJWT)
	if err != nil {
		return httputil.NewError(http.StatusBadRequest, err)
	}

	// build our hmac-d redirect URL with our session, pointing back to the
	// proxy's callback URL which is responsible for setting our new route-session
	uri := urlutil.NewSignedURL(s.sharedKey, callbackURL)
	httputil.Redirect(w, r, uri.String(), http.StatusFound)
	return nil
}

// PersistSession stores session and user data in the databroker.
func (s *Stateful) PersistSession(
	ctx context.Context,
	_ http.ResponseWriter,
	sessionState *sessions.State,
	claims identity.SessionClaims,
	accessToken *oauth2.Token,
) error {
	sessionExpiry := timestamppb.New(time.Now().Add(s.sessionDuration))
	idTokenIssuedAt := timestamppb.New(sessionState.IssuedAt.Time())

	sess := &session.Session{
		Id:         sessionState.ID,
		UserId:     sessionState.UserID(),
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
	sess.SetRawIDToken(claims.RawIDToken)
	sess.AddClaims(claims.Flatten())

	u, _ := user.Get(ctx, s.dataBrokerClient, sess.GetUserId())
	if u == nil {
		// if no user exists yet, create a new one
		u = &user.User{
			Id: sess.GetUserId(),
		}
	}
	populateUserFromClaims(u, claims.Claims)
	_, err := databroker.Put(ctx, s.dataBrokerClient, u)
	if err != nil {
		return fmt.Errorf("authenticate: error saving user: %w", err)
	}

	res, err := session.Put(ctx, s.dataBrokerClient, sess)
	if err != nil {
		return fmt.Errorf("authenticate: error saving session: %w", err)
	}
	sessionState.DatabrokerServerVersion = res.GetServerVersion()
	sessionState.DatabrokerRecordVersion = res.GetRecord().GetVersion()

	return nil
}

// GetUserInfoData returns user info data associated with the given request (if
// any).
func (s *Stateful) GetUserInfoData(
	r *http.Request, sessionState *sessions.State,
) handlers.UserInfoData {
	var isImpersonated bool
	pbSession, err := session.Get(r.Context(), s.dataBrokerClient, sessionState.ID)
	if sid := pbSession.GetImpersonateSessionId(); sid != "" {
		pbSession, err = session.Get(r.Context(), s.dataBrokerClient, sid)
		isImpersonated = true
	}
	if err != nil {
		pbSession = &session.Session{
			Id: sessionState.ID,
		}
	}

	pbUser, err := user.Get(r.Context(), s.dataBrokerClient, pbSession.GetUserId())
	if err != nil {
		pbUser = &user.User{
			Id: pbSession.GetUserId(),
		}
	}
	return handlers.UserInfoData{
		IsImpersonated: isImpersonated,
		Session:        pbSession,
		User:           pbUser,
	}
}

// RevokeSession revokes the session associated with the provided request,
// returning the ID token from the revoked session.
func (s *Stateful) RevokeSession(
	ctx context.Context,
	_ *http.Request,
	authenticator identity.Authenticator,
	sessionState *sessions.State,
) string {
	if sessionState == nil {
		return ""
	}

	// Note: session.Delete() cannot be used safely, because the identity
	// manager expects to be able to read both session ID and user ID from
	// deleted session records. Instead, we match the behavior used in the
	// identity manager itself: fetch the existing databroker session record,
	// explicitly set the DeletedAt timestamp, and Put() that record back.

	res, err := s.dataBrokerClient.Get(ctx, &databroker.GetRequest{
		Type: grpcutil.GetTypeURL(new(session.Session)),
		Id:   sessionState.ID,
	})
	if err != nil {
		err = fmt.Errorf("couldn't get session to be revoked: %w", err)
		log.Ctx(ctx).Warn().Err(err).Msg("authenticate: failed to revoke access token")
		return ""
	}

	record := res.GetRecord()

	var sess session.Session
	if err := record.GetData().UnmarshalTo(&sess); err != nil {
		err = fmt.Errorf("couldn't unmarshal data of session to be revoked: %w", err)
		log.Ctx(ctx).Warn().Err(err).Msg("authenticate: failed to revoke access token")
		return ""
	}

	var rawIDToken string
	if sess.OauthToken != nil {
		rawIDToken = sess.GetIdToken().GetRaw()
		if err := authenticator.Revoke(ctx, manager.FromOAuthToken(sess.OauthToken)); err != nil {
			log.Ctx(ctx).Warn().Err(err).Msg("authenticate: failed to revoke access token")
		}
	}

	record.DeletedAt = timestamppb.Now()
	_, err = s.dataBrokerClient.Put(ctx, &databroker.PutRequest{
		Records: []*databroker.Record{record},
	})
	if err != nil {
		log.Ctx(ctx).Warn().Err(err).
			Msg("authenticate: failed to delete session from session store")
	}
	return rawIDToken
}

// VerifySession checks that an existing session is still valid.
func (s *Stateful) VerifySession(
	ctx context.Context, _ *http.Request, sessionState *sessions.State,
) error {
	sess, err := session.Get(ctx, s.dataBrokerClient, sessionState.ID)
	if err != nil {
		return fmt.Errorf("session not found in databroker: %w", err)
	}
	return sess.Validate()
}

// LogAuthenticateEvent is a no-op for the stateful authentication flow.
func (s *Stateful) LogAuthenticateEvent(*http.Request) {}

// AuthenticateSignInURL returns a URL to redirect the user to the authenticate
// domain.
func (s *Stateful) AuthenticateSignInURL(
	_ context.Context, queryParams url.Values, redirectURL *url.URL, idpID string,
) (string, error) {
	signinURL := s.authenticateURL.ResolveReference(&url.URL{
		Path: "/.pomerium/sign_in",
	})

	if queryParams == nil {
		queryParams = url.Values{}
	}
	queryParams.Set(urlutil.QueryRedirectURI, redirectURL.String())
	queryParams.Set(urlutil.QueryIdentityProviderID, idpID)
	signinURL.RawQuery = queryParams.Encode()
	redirectTo := urlutil.NewSignedURL(s.sharedKey, signinURL).String()

	return redirectTo, nil
}

// GetIdentityProviderIDForURLValues returns the identity provider ID
// associated with the given URL values.
func (s *Stateful) GetIdentityProviderIDForURLValues(vs url.Values) string {
	if id := vs.Get(urlutil.QueryIdentityProviderID); id != "" {
		return id
	}
	return s.defaultIdentityProviderID
}

// Callback handles a redirect to a route domain once signed in.
func (s *Stateful) Callback(w http.ResponseWriter, r *http.Request) error {
	if err := s.VerifySignature(r); err != nil {
		return httputil.NewError(http.StatusBadRequest, err)
	}

	redirectURLString := r.FormValue(urlutil.QueryRedirectURI)
	encryptedSession := r.FormValue(urlutil.QuerySessionEncrypted)

	redirectURL, err := urlutil.ParseAndValidateURL(redirectURLString)
	if err != nil {
		return httputil.NewError(http.StatusBadRequest, err)
	}

	encryptedJWT, err := base64.URLEncoding.DecodeString(encryptedSession)
	if err != nil {
		return fmt.Errorf("proxy: malfromed callback token: %w", err)
	}

	rawJWT, err := cryptutil.Decrypt(s.sharedCipher, encryptedJWT, nil)
	if err != nil {
		return fmt.Errorf("proxy: callback token decrypt error: %w", err)
	}

	// save the session state
	if err = s.sessionStore.SaveSession(w, r, rawJWT); err != nil {
		return httputil.NewError(http.StatusInternalServerError, fmt.Errorf("proxy: error saving session state: %w", err))
	}

	// if programmatic, encode the session jwt as a query param
	if isProgrammatic := r.FormValue(urlutil.QueryIsProgrammatic); isProgrammatic == "true" {
		q := redirectURL.Query()
		q.Set(urlutil.QueryPomeriumJWT, string(rawJWT))
		redirectURL.RawQuery = q.Encode()
	}

	// redirect
	httputil.Redirect(w, r, redirectURL.String(), http.StatusFound)
	return nil
}
