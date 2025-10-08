package authenticateflow

import (
	"context"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"net/url"
	"strings"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"go.opentelemetry.io/otel"
	oteltrace "go.opentelemetry.io/otel/trace"
	"golang.org/x/oauth2"
	googlegrpc "google.golang.org/grpc"
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
	"github.com/pomerium/pomerium/pkg/protoutil"
	"github.com/pomerium/pomerium/pkg/ssh/pending"
	"github.com/pomerium/pomerium/pkg/telemetry/trace"
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

	authenticateURL *url.URL

	dataBrokerClient databroker.DataBrokerServiceClient

	defaultIdentityProviderID string

	codeAccessor pending.CodeAcessor
}

// NewStateful initializes the authentication flow for the given configuration
// and session store.
func NewStateful(
	ctx context.Context,
	tracerProvider oteltrace.TracerProvider,
	cfg *config.Config,
	sessionStore sessions.SessionStore,
	outboundGrpcConn *grpc.CachedOutboundGRPClientConn,
) (*Stateful, error) {
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

	dataBrokerConn, err := outboundGrpcConn.Get(ctx,
		&grpc.OutboundOptions{
			OutboundPort:   cfg.OutboundPort,
			InstallationID: cfg.Options.InstallationID,
			ServiceName:    cfg.Options.Services,
			SignedJWTKey:   s.sharedKey,
		}, googlegrpc.WithStatsHandler(trace.NewClientStatsHandler(
			otelgrpc.NewClientHandler(otelgrpc.WithTracerProvider(tracerProvider)),
			outboundDatabrokerTraceClientOpts...,
		)))
	if err != nil {
		return nil, err
	}

	s.dataBrokerClient = databroker.NewDataBrokerServiceClient(dataBrokerConn)
	s.codeAccessor = pending.NewDistributedCodeAccessor(s.dataBrokerClient)
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

	additionalHosts := strings.Split(r.FormValue(urlutil.QueryAdditionalHosts), ",")

	callbackURL, err := urlutil.GetCallbackURL(r, encodedJWT, additionalHosts)
	if err != nil {
		return httputil.NewError(http.StatusBadRequest, err)
	}

	// build our hmac-d redirect URL with our session, pointing back to the
	// proxy's callback URL which is responsible for setting our new route-session
	uri := urlutil.NewSignedURL(s.sharedKey, callbackURL)
	httputil.Redirect(w, r, uri.String(), http.StatusFound)
	return nil
}

func getSbrId(r *http.Request, state *sessions.State) string {
	query := r.URL.Query()
	if query.Has(urlutil.QueryBindSession) {
		sbrID := query.Get(urlutil.QueryBindSession)
		if state == nil {
			panic("bug: state missing")
		}
		return sbrID
	} else {
		return query.Get("user_code")
	}
}

func (s *Stateful) validateStateOrNew(
	r *http.Request,
	state *sessions.State,
	sbrID string,
	sbr *session.SessionBindingRequest,
) (uri string, redirect bool, err error) {
	if state != nil {
		if err := s.VerifySession(r.Context(), r, state); err != nil {
			// invalid session, need to reauthenticate
			state = nil
		}
	}
	if state == nil {
		// authenticate and redirect back here
		values := url.Values{}
		values.Set(urlutil.QueryBindSession, sbrID)
		values.Set(urlutil.QueryIdentityProviderID, sbr.IdpId)
		redirectURL := s.authenticateURL.ResolveReference(&url.URL{
			RawQuery: values.Encode(),
		})
		uri, err := s.AuthenticateSignInURL(r.Context(), values, redirectURL, sbr.IdpId, nil)
		if err != nil {
			return "", false, httputil.NewError(http.StatusInternalServerError, err)
		}
		return uri, true, nil
	}
	return "", false, nil
}

func (s *Stateful) AuthenticatePendingSession(
	w http.ResponseWriter,
	r *http.Request,
	state *sessions.State,
) error {
	sbrID := getSbrId(r, state)
	logger := slog.Default().With("code", sbrID)

	sbr, ok := s.codeAccessor.GetBindingRequest(r.Context(), pending.CodeID(sbrID))
	if !ok {
		logger.Error("code no longer valid")
		return httputil.NewError(http.StatusBadRequest, fmt.Errorf("code invalid"))
	}
	uri, redirect, err := s.validateStateOrNew(r, state, sbrID, sbr)
	if err != nil {
		return err
	}
	if redirect {
		logger.With("uri", uri).Info("redirecting")
		httputil.Redirect(w, r, uri, http.StatusFound)
		return nil
	}

	identityBinding, hasIdentity, err := s.hasIdentityBinding(r.Context(), sbr)
	if err != nil {
		return err
	}
	if hasIdentity {
		if !isValidIdentity(identityBinding, state, sbr) {
			identityBinding = nil
		}
	}

	switch r.Method {
	case http.MethodGet:
		if identityBinding == nil {
			s.handleSignIn(w, r, state, sbr)
			return nil
		}
	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			return err
		}
		confirmed := r.Form.Get("confirm") == "true"
		createIDBinding := r.Form.Get("create_id_binding") == "true"
		logger.With("allow", confirmed).With("persist-identity", createIDBinding)
		if !confirmed {
			logger.Info("revoking code")
			err := s.codeAccessor.RevokeCode(r.Context(), pending.CodeID(sbrID))
			if err != nil {
				logger.With("err", err).Error("failed to revoke code")
			}
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("code revoked"))
			return nil
		}
		if createIDBinding {
			logger.Info("persisting identity")
			if err := s.associateIdentity(r.Context(), sbr, state); err != nil {
				log.Ctx(r.Context()).Err(err).Msg("failed to persist IdentityBinding")
			}
		}
	default:
		logger.Error("method not allowed")
		return httputil.NewError(http.StatusMethodNotAllowed, fmt.Errorf("method not allowed"))
	}
	// sign in successful or identity was already persisted.
	expiresAt, err := s.createSessionBinding(r.Context(), state, sbr.Key)
	if err != nil {
		return err
	}
	if identityBinding != nil {
		expiresAt = nil // session will be bound to an identity that is valid until revoked
	}
	handlers.SignInSuccess(handlers.SignInSuccessData{
		UserInfoData: s.GetUserInfoData(r, state),
		ExpiresAt:    expiresAt,
		Protocol:     sbr.Protocol,
	}).ServeHTTP(w, r)
	return nil
}

func isValidIdentity(
	ib *session.IdentityBinding,
	state *sessions.State,
	sbr *session.SessionBindingRequest,
) bool {
	return ib.IdpId == state.IdentityProviderID &&
		ib.Protocol == sbr.Protocol &&
		ib.UserId == state.UserID()
}

func (s *Stateful) hasIdentityBinding(
	ctx context.Context,
	sbr *session.SessionBindingRequest,
) (*session.IdentityBinding, bool, error) {
	var identityBinding session.IdentityBinding
	resp, err := s.dataBrokerClient.Get(ctx, &databroker.GetRequest{
		Type: "type.googleapis.com/session.IdentityBinding",
		Id:   sbr.Key,
	})
	if databroker.IsNotFound(err) {
		return nil, false, nil
	} else if err != nil {
		return nil, false, httputil.NewError(http.StatusInternalServerError, err)
	}
	if err := resp.GetRecord().GetData().UnmarshalTo(&identityBinding); err != nil {
		return nil, false, err
	}
	return &identityBinding, true, nil
}

func (s *Stateful) associateIdentity(ctx context.Context, sbr *session.SessionBindingRequest, state *sessions.State) error {
	ib := session.IdentityBinding{
		Protocol: session.ProtocolSSH,
		UserId:   state.UserID(),
		IdpId:    state.IdentityProviderID,
	}
	_, err := s.dataBrokerClient.Put(ctx, &databroker.PutRequest{
		Records: []*databroker.Record{
			{
				Type: "type.googleapis.com/session.IdentityBinding",
				Id:   sbr.Key,
				Data: protoutil.NewAny(&ib),
			},
		},
	})
	return err
}

func (s *Stateful) handleSignIn(w http.ResponseWriter, r *http.Request, state *sessions.State, sbr *session.SessionBindingRequest) {
	// redirect := urlutil.NewSignedURL(s.sharedKey, r.URL)
	handlers.SignInVerify(handlers.SignInVerifyData{
		UserInfoData: s.GetUserInfoData(r, state),
		RedirectURL:  r.URL.String(),
		IssuedAt:     sbr.CreatedAt.AsTime(),
		ExpiresAt:    sbr.ExpiresAt.AsTime(),
		SourceAddr:   sbr.Details[session.DetailSourceAddr],
		Protocol:     sbr.Protocol,
	}).ServeHTTP(w, r)
}

func (s *Stateful) createSessionBinding(
	ctx context.Context,
	state *sessions.State,
	sessionID string,
) (expiresAt *time.Time, err error) {
	expiry, err := s.sessionExpiresAt(ctx, state)
	if err != nil {
		return nil, err
	}
	if expiry == nil {
		defaultT := time.Now().Add(time.Hour * 48)
		expiry = &defaultT
	}
	_, err = s.dataBrokerClient.Put(ctx, &databroker.PutRequest{
		Records: []*databroker.Record{
			{
				Type: "type.googleapis.com/session.SessionBinding",
				Id:   sessionID,
				Data: protoutil.NewAny(&session.SessionBinding{
					Protocol:  session.ProtocolSSH,
					SessionId: state.ID,
					IssuedAt:  timestamppb.New(state.IssuedAt.Time()),
					ExpiresAt: timestamppb.New(*expiry),
				}),
			},
		},
	})
	if err != nil {
		slog.Default().With("err", err).Error("failed to persist session binding")
		return nil, err
	}
	return expiry, nil
}

// PersistSession stores session and user data in the databroker.
func (s *Stateful) PersistSession(
	ctx context.Context,
	_ http.ResponseWriter,
	sessionState *sessions.State,
	claims identity.SessionClaims,
	accessToken *oauth2.Token,
) error {
	now := timeNow()
	sessionExpiry := timestamppb.New(now.Add(s.sessionDuration))

	sess := session.New(sessionState.IdentityProviderID, sessionState.ID)
	sess.UserId = sessionState.UserID()
	sess.IssuedAt = timestamppb.New(now)
	sess.AccessedAt = timestamppb.New(now)
	sess.ExpiresAt = sessionExpiry
	sess.OauthToken = manager.ToOAuthToken(accessToken)
	sess.Audience = sessionState.Audience
	sess.SetRawIDToken(claims.RawIDToken)
	sess.AddClaims(claims.Flatten())

	u, _ := user.Get(ctx, s.dataBrokerClient, sess.GetUserId())
	if u == nil {
		// if no user exists yet, create a new one
		u = &user.User{
			Id: sess.GetUserId(),
		}
	}
	u.PopulateFromClaims(claims.Claims)
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
		pbSession = session.New(sessionState.IdentityProviderID, sessionState.ID)
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
		log.Ctx(ctx).Error().Err(err).Msg("authenticate: failed to revoke access token")
		return ""
	}

	record := res.GetRecord()

	var sess session.Session
	if err := record.GetData().UnmarshalTo(&sess); err != nil {
		err = fmt.Errorf("couldn't unmarshal data of session to be revoked: %w", err)
		log.Ctx(ctx).Error().Err(err).Msg("authenticate: failed to revoke access token")
		return ""
	}

	var rawIDToken string
	if sess.OauthToken != nil {
		rawIDToken = sess.GetIdToken().GetRaw()
		if err := authenticator.Revoke(ctx, manager.FromOAuthToken(sess.OauthToken)); err != nil {
			log.Ctx(ctx).Error().Err(err).Msg("authenticate: failed to revoke access token")
		}
	}

	record.DeletedAt = timestamppb.Now()
	_, err = s.dataBrokerClient.Put(ctx, &databroker.PutRequest{
		Records: []*databroker.Record{record},
	})
	if err != nil {
		log.Ctx(ctx).Error().Err(err).
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

func (s *Stateful) sessionExpiresAt(ctx context.Context, sessionState *sessions.State) (*time.Time, error) {
	sess, err := session.Get(ctx, s.dataBrokerClient, sessionState.ID)
	if err != nil {
		return nil, fmt.Errorf("session not found in databroker: %w", err)
	}

	if expiresAt := sess.GetExpiresAt(); expiresAt != nil {
		t := expiresAt.AsTime()
		return &t, nil
	}
	if expiresAt := sess.GetOauthToken().GetExpiresAt(); expiresAt != nil {
		t := expiresAt.AsTime()
		return &t, nil
	}
	return nil, nil
}

// LogAuthenticateEvent is a no-op for the stateful authentication flow.
func (s *Stateful) LogAuthenticateEvent(*http.Request) {}

// AuthenticateSignInURL returns a URL to redirect the user to the authenticate
// domain.
func (s *Stateful) AuthenticateSignInURL(
	ctx context.Context,
	queryParams url.Values,
	redirectURL *url.URL,
	idpID string,
	additionalHosts []string,
) (string, error) {
	signinURL := s.authenticateURL.ResolveReference(&url.URL{
		Path: "/.pomerium/sign_in",
	})

	if queryParams == nil {
		queryParams = url.Values{}
	}
	queryParams.Set(urlutil.QueryRedirectURI, redirectURL.String())
	queryParams.Set(urlutil.QueryIdentityProviderID, idpID)
	if len(additionalHosts) > 0 {
		queryParams.Set(urlutil.QueryAdditionalHosts, strings.Join(additionalHosts, ","))
	}
	otel.GetTextMapPropagator().Inject(ctx, trace.PomeriumURLQueryCarrier(queryParams))
	signinURL.RawQuery = queryParams.Encode()
	redirectTo := urlutil.NewSignedURL(s.sharedKey, signinURL).String()

	return redirectTo, nil
}

func (s *Stateful) DecryptURLValues(vs url.Values) (url.Values, error) {
	vals := maps.Clone(vs)
	if id := vs.Get(urlutil.QueryIdentityProviderID); id == "" {
		vals.Set(urlutil.QueryIdentityProviderID, s.defaultIdentityProviderID)
	}
	return vals, nil
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

	// Redirect chaining for multi-domain login.
	additionalHosts := r.URL.Query().Get(urlutil.QueryAdditionalHosts)
	if additionalHosts != "" {
		nextHops := strings.Split(additionalHosts, ",")
		log.Ctx(r.Context()).Debug().Strs("next-hops", nextHops).Msg("multi-domain login callback")

		callbackURL, err := urlutil.GetCallbackURL(r, encryptedSession, nextHops[1:])
		if err != nil {
			return httputil.NewError(http.StatusInternalServerError,
				fmt.Errorf("proxy: couldn't get next hop callback URL: %w", err))
		}
		callbackURL.Host = nextHops[0]
		signedCallbackURL := urlutil.NewSignedURL(s.sharedKey, callbackURL)
		httputil.Redirect(w, r, signedCallbackURL.String(), http.StatusFound)
		return nil
	}

	// redirect
	httputil.Redirect(w, r, redirectURL.String(), http.StatusFound)
	return nil
}
