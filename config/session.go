package config

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	oteltrace "go.opentelemetry.io/otel/trace"
	"golang.org/x/sync/singleflight"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/internal/encoding"
	"github.com/pomerium/pomerium/internal/encoding/jws"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/jwtutil"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/internal/sessions/cookie"
	"github.com/pomerium/pomerium/internal/sessions/header"
	"github.com/pomerium/pomerium/internal/sessions/queryparam"
	"github.com/pomerium/pomerium/internal/telemetry"
	"github.com/pomerium/pomerium/internal/telemetry/metrics"
	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/pkg/authenticateapi"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	identitypb "github.com/pomerium/pomerium/pkg/grpc/identity"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpc/user"
	"github.com/pomerium/pomerium/pkg/grpcutil"
	"github.com/pomerium/pomerium/pkg/identity"
	"github.com/pomerium/pomerium/pkg/protoutil"
	"github.com/pomerium/pomerium/pkg/storage"
)

// A SessionStore saves and loads sessions based on the options.
type SessionStore struct {
	store   sessions.SessionStore
	loader  sessions.SessionLoader
	options *Options
	encoder encoding.MarshalUnmarshaler
}

var _ sessions.SessionStore = (*SessionStore)(nil)

// NewSessionStore creates a new SessionStore from the Options.
func NewSessionStore(options *Options) (*SessionStore, error) {
	store := &SessionStore{
		options: options,
	}

	sharedKey, err := options.GetSharedKey()
	if err != nil {
		return nil, fmt.Errorf("config/sessions: shared_key is required: %w", err)
	}

	store.encoder, err = jws.NewHS256Signer(sharedKey)
	if err != nil {
		return nil, fmt.Errorf("config/sessions: invalid session encoder: %w", err)
	}

	store.store, err = cookie.NewStore(func() cookie.Options {
		return cookie.Options{
			Name:     options.CookieName,
			Domain:   options.CookieDomain,
			Secure:   true,
			HTTPOnly: options.CookieHTTPOnly,
			Expire:   options.CookieExpire,
			SameSite: options.GetCookieSameSite(),
		}
	}, store.encoder)
	if err != nil {
		return nil, err
	}
	headerStore := header.NewStore(store.encoder)
	queryParamStore := queryparam.NewStore(store.encoder, urlutil.QuerySession)
	store.loader = sessions.MultiSessionLoader(store.store, headerStore, queryParamStore)

	return store, nil
}

// ClearSession clears the session.
func (store *SessionStore) ClearSession(w http.ResponseWriter, r *http.Request) {
	store.store.ClearSession(w, r)
}

// LoadSession loads the session.
func (store *SessionStore) LoadSession(r *http.Request) (string, error) {
	return store.loader.LoadSession(r)
}

// LoadSessionHandle loads the session handle from a request.
func (store *SessionStore) LoadSessionHandle(r *http.Request) (*session.Handle, error) {
	rawJWT, err := store.loader.LoadSession(r)
	if err != nil {
		return nil, err
	}

	var h session.Handle
	err = store.encoder.Unmarshal([]byte(rawJWT), &h)
	if err != nil {
		return nil, err
	}

	return &h, nil
}

// LoadSessionHandleAndCheckIDP loads the session handle from a request and checks that the idp id matches.
func (store *SessionStore) LoadSessionHandleAndCheckIDP(r *http.Request) (*session.Handle, error) {
	h, err := store.LoadSessionHandle(r)
	if err != nil {
		return nil, err
	}

	// confirm that the identity provider id matches the handle
	if h.IdentityProviderId != "" {
		idp, err := store.options.GetIdentityProviderForRequestURL(urlutil.GetAbsoluteURL(r).String())
		if err != nil {
			return nil, err
		}

		if idp.GetId() != h.IdentityProviderId {
			return nil, fmt.Errorf("unexpected session handle identity provider id: %s != %s",
				idp.GetId(), h.IdentityProviderId)
		}
	}

	return h, nil
}

// SaveSession saves the session.
func (store *SessionStore) SaveSession(w http.ResponseWriter, r *http.Request, v any) error {
	return store.store.SaveSession(w, r, v)
}

type IncomingIDPTokenSessionCreator interface {
	CreateSession(ctx context.Context, cfg *Config, policy *Policy, r *http.Request) (*session.Session, error)
}

type incomingIDPTokenSessionCreator struct {
	accessTokenSessionsCreatedCount    metric.Int64Counter
	accessTokenSessionsCachedCount     metric.Int64Counter
	accessTokenCreateSessionDuration   metric.Int64Histogram
	identityTokenSessionsCreatedCount  metric.Int64Counter
	identityTokenSessionsCachedCount   metric.Int64Counter
	identityTokenCreateSessionDuration metric.Int64Histogram

	timeNow      func() time.Time
	getRecord    func(ctx context.Context, recordType, recordID string) (*databroker.Record, error)
	putRecords   func(ctx context.Context, records []*databroker.Record) error
	singleflight singleflight.Group

	telemetry telemetry.Component
}

func NewIncomingIDPTokenSessionCreator(
	tracerProvider oteltrace.TracerProvider,
	getRecord func(ctx context.Context, recordType, recordID string) (*databroker.Record, error),
	putRecords func(ctx context.Context, records []*databroker.Record) error,
) IncomingIDPTokenSessionCreator {
	return &incomingIDPTokenSessionCreator{
		accessTokenSessionsCreatedCount: metrics.Int64Counter("config.idp_token_session_creator.access_token.sessions_created",
			metric.WithDescription("Number of sessions created from IDP access tokens."),
			metric.WithUnit("{session}")),
		accessTokenSessionsCachedCount: metrics.Int64Counter("config.idp_token_session_creator.access_token.sessions_cached",
			metric.WithDescription("Number of sessions cached from IDP access tokens."),
			metric.WithUnit("{session}")),
		accessTokenCreateSessionDuration: metrics.Int64Histogram("config.idp_token_session_creator.access_token.create_session.duration",
			metric.WithDescription("Duration of create session from IDP access tokens."),
			metric.WithUnit("ms")),
		identityTokenSessionsCreatedCount: metrics.Int64Counter("config.idp_token_session_creator.identity_token.sessions_created",
			metric.WithDescription("Number of sessions created from IDP identity tokens."),
			metric.WithUnit("{session}")),
		identityTokenSessionsCachedCount: metrics.Int64Counter("config.idp_token_session_creator.identity_token.sessions_cached",
			metric.WithDescription("Number of sessions cached from IDP identity tokens."),
			metric.WithUnit("{session}")),
		identityTokenCreateSessionDuration: metrics.Int64Histogram("config.idp_token_session_creator.identity_token.create_session.duration",
			metric.WithDescription("Duration of create session from IDP identity tokens."),
			metric.WithUnit("ms")),

		timeNow:    time.Now,
		getRecord:  getRecord,
		putRecords: putRecords,

		telemetry: *telemetry.NewComponent(tracerProvider, zerolog.InfoLevel, "idp-token-session-creator"),
	}
}

// CreateSession attempts to create a session for incoming idp access and
// identity tokens. If no access or identity token is passed ErrNoSessionFound will be returned.
// If the tokens are not valid an error will be returned.
func (c *incomingIDPTokenSessionCreator) CreateSession(
	ctx context.Context,
	cfg *Config,
	policy *Policy,
	r *http.Request,
) (session *session.Session, err error) {
	ctx, op := c.telemetry.Start(ctx, "CreateSession")
	defer op.Complete()

	if rawAccessToken, ok := cfg.GetIncomingIDPAccessTokenForPolicy(policy, r); ok {
		return c.createSessionForAccessToken(ctx, cfg, policy, rawAccessToken)
	}

	if rawIdentityToken, ok := cfg.GetIncomingIDPIdentityTokenForPolicy(policy, r); ok {
		return c.createSessionForIdentityToken(ctx, cfg, policy, rawIdentityToken)
	}

	return nil, sessions.ErrNoSessionFound
}

func (c *incomingIDPTokenSessionCreator) createSessionForAccessToken(
	ctx context.Context,
	cfg *Config,
	policy *Policy,
	rawAccessToken string,
) (*session.Session, error) {
	ctx, op := c.telemetry.Start(ctx, "createSessionForAccessToken")
	defer op.Complete()

	start := time.Now()

	idp, err := cfg.Options.GetIdentityProviderForPolicy(policy)
	if err != nil {
		return nil, op.Failure(fmt.Errorf("error getting identity provider to verify access token: %w", err))
	}

	sessionID := getAccessTokenSessionID(idp, rawAccessToken)
	res, err, _ := c.singleflight.Do(sessionID, func() (any, error) {
		s, err := c.getSession(ctx, sessionID)
		if err == nil {
			c.accessTokenSessionsCachedCount.Add(ctx, 1)
			return s, nil
		} else if !storage.IsNotFound(err) {
			return nil, err
		}

		authenticateURL, transport, err := cfg.resolveAuthenticateURL()
		if err != nil {
			return nil, fmt.Errorf("error resolving authenticate url to verify access token: %w", err)
		}

		res, err := authenticateapi.New(authenticateURL, transport).VerifyAccessToken(ctx, &authenticateapi.VerifyAccessTokenRequest{
			AccessToken:        rawAccessToken,
			IdentityProviderID: idp.GetId(),
		})
		if err != nil {
			return nil, fmt.Errorf("error verifying access token: %w", err)
		} else if !res.Valid {
			return nil, fmt.Errorf("%w: invalid access token", sessions.ErrInvalidSession)
		}

		s = c.newSessionFromIDPClaims(cfg, idp.Id, sessionID, res.Claims)
		s.OauthToken = &session.OAuthToken{
			TokenType:   "Bearer",
			AccessToken: rawAccessToken,
			ExpiresAt:   s.ExpiresAt,
		}

		u, err := c.getUser(ctx, s.GetUserId())
		if storage.IsNotFound(err) {
			u = &user.User{Id: s.GetUserId()}
		} else if err != nil {
			return nil, fmt.Errorf("error retrieving existing user: %w", err)
		}
		c.fillUserFromIDPClaims(u, res.Claims)

		err = c.putSessionAndUser(ctx, s, u)
		if err != nil {
			return nil, fmt.Errorf("error saving session and user: %w", err)
		}

		c.accessTokenSessionsCreatedCount.Add(ctx, 1)
		return s, nil
	})
	if err != nil {
		return nil, op.Failure(err)
	}

	c.accessTokenCreateSessionDuration.Record(ctx, time.Since(start).Milliseconds())
	return res.(*session.Session), nil
}

func (c *incomingIDPTokenSessionCreator) createSessionForIdentityToken(
	ctx context.Context,
	cfg *Config,
	policy *Policy,
	rawIdentityToken string,
) (*session.Session, error) {
	ctx, op := c.telemetry.Start(ctx, "createSessionForIdentityToken")
	defer op.Complete()

	start := time.Now()

	idp, err := cfg.Options.GetIdentityProviderForPolicy(policy)
	if err != nil {
		return nil, op.Failure(fmt.Errorf("error getting identity provider to verify identity token: %w", err))
	}

	sessionID := getIdentityTokenSessionID(idp, rawIdentityToken)
	res, err, _ := c.singleflight.Do(sessionID, func() (any, error) {
		s, err := c.getSession(ctx, sessionID)
		if err == nil {
			c.identityTokenSessionsCachedCount.Add(ctx, 1)
			return s, nil
		} else if !storage.IsNotFound(err) {
			return nil, err
		}

		authenticateURL, transport, err := cfg.resolveAuthenticateURL()
		if err != nil {
			return nil, fmt.Errorf("error resolving authenticate url to verify identity token: %w", err)
		}

		res, err := authenticateapi.New(authenticateURL, transport).VerifyIdentityToken(ctx, &authenticateapi.VerifyIdentityTokenRequest{
			IdentityToken:      rawIdentityToken,
			IdentityProviderID: idp.GetId(),
		})
		if err != nil {
			return nil, fmt.Errorf("error verifying identity token: %w", err)
		} else if !res.Valid {
			return nil, fmt.Errorf("%w: invalid identity token", sessions.ErrInvalidSession)
		}

		s = c.newSessionFromIDPClaims(cfg, idp.Id, sessionID, res.Claims)
		s.SetRawIDToken(rawIdentityToken)

		u, err := c.getUser(ctx, s.GetUserId())
		if errors.Is(err, storage.ErrNotFound) {
			u = &user.User{Id: s.GetUserId()}
		} else if err != nil {
			return nil, fmt.Errorf("error retrieving existing user: %w", err)
		}
		c.fillUserFromIDPClaims(u, res.Claims)

		err = c.putSessionAndUser(ctx, s, u)
		if err != nil {
			return nil, fmt.Errorf("error saving session and user: %w", err)
		}

		c.identityTokenSessionsCreatedCount.Add(ctx, 1)
		return s, nil
	})
	if err != nil {
		return nil, op.Failure(err)
	}

	c.identityTokenCreateSessionDuration.Record(ctx, time.Since(start).Milliseconds())
	return res.(*session.Session), nil
}

func (c *incomingIDPTokenSessionCreator) newSessionFromIDPClaims(
	cfg *Config,
	idpID string,
	sessionID string,
	claims jwtutil.Claims,
) *session.Session {
	now := c.timeNow()
	s := session.New(idpID, sessionID)
	s.Id = sessionID
	if userID, ok := claims.GetUserID(); ok {
		s.UserId = userID
	}
	if issuedAt, ok := claims.GetIssuedAt(); ok {
		s.IssuedAt = timestamppb.New(issuedAt)
	} else {
		s.IssuedAt = timestamppb.New(now)
	}
	if expiresAt, ok := claims.GetExpirationTime(); ok {
		s.ExpiresAt = timestamppb.New(expiresAt)
	} else {
		s.ExpiresAt = timestamppb.New(now.Add(cfg.Options.CookieExpire))
	}
	s.AccessedAt = timestamppb.New(now)
	s.AddClaims(identity.Claims(claims).Flatten())
	if aud, ok := claims.GetAudience(); ok {
		s.Audience = aud
	}
	s.RefreshDisabled = true
	return s
}

func (c *incomingIDPTokenSessionCreator) fillUserFromIDPClaims(
	u *user.User,
	claims jwtutil.Claims,
) {
	if userID, ok := claims.GetUserID(); ok {
		u.Id = userID
	}
	if name, ok := claims.GetString("name"); ok {
		u.Name = name
	}
	if email, ok := claims.GetString("email"); ok {
		u.Email = email
	}
	u.AddClaims(identity.Claims(claims).Flatten())
}

func (c *incomingIDPTokenSessionCreator) getSession(ctx context.Context, sessionID string) (*session.Session, error) {
	ctx, op := c.telemetry.Start(ctx, "getSession", attribute.String("session-id", sessionID))
	defer op.Complete()

	record, err := c.getRecord(ctx, grpcutil.GetTypeURL(new(session.Session)), sessionID)
	if databroker.IsNotFound(err) {
		return nil, err
	} else if err != nil {
		return nil, op.Failure(err)
	}

	msg, err := record.GetData().UnmarshalNew()
	if err != nil {
		return nil, storage.ErrNotFound
	}

	s, ok := msg.(*session.Session)
	if !ok {
		return nil, storage.ErrNotFound
	}

	return s, nil
}

func (c *incomingIDPTokenSessionCreator) getUser(ctx context.Context, userID string) (*user.User, error) {
	ctx, op := c.telemetry.Start(ctx, "getUser", attribute.String("user-id", userID))
	defer op.Complete()

	record, err := c.getRecord(ctx, grpcutil.GetTypeURL(new(user.User)), userID)
	if databroker.IsNotFound(err) {
		return nil, err
	} else if err != nil {
		return nil, op.Failure(err)
	}

	msg, err := record.GetData().UnmarshalNew()
	if err != nil {
		return nil, storage.ErrNotFound
	}

	u, ok := msg.(*user.User)
	if !ok {
		return nil, storage.ErrNotFound
	}

	return u, nil
}

func (c *incomingIDPTokenSessionCreator) putSessionAndUser(ctx context.Context, s *session.Session, u *user.User) error {
	ctx, op := c.telemetry.Start(ctx, "putSessionAndUser")
	defer op.Complete()

	var records []*databroker.Record
	if id := s.GetId(); id != "" {
		records = append(records, &databroker.Record{
			Type: grpcutil.GetTypeURL(s),
			Id:   id,
			Data: protoutil.NewAny(s),
		})
	}
	if id := u.GetId(); id != "" {
		records = append(records, &databroker.Record{
			Type: grpcutil.GetTypeURL(u),
			Id:   id,
			Data: protoutil.NewAny(u),
		})
	}

	err := c.putRecords(ctx, records)
	if err != nil {
		return op.Failure(err)
	}

	return nil
}

// GetIncomingIDPAccessTokenForPolicy returns the raw idp access token from a request if there is one.
func (cfg *Config) GetIncomingIDPAccessTokenForPolicy(policy *Policy, r *http.Request) (rawAccessToken string, ok bool) {
	bearerTokenFormat := BearerTokenFormatUnknown
	if cfg.Options != nil && cfg.Options.BearerTokenFormat != nil {
		bearerTokenFormat = *cfg.Options.BearerTokenFormat
	}
	if policy != nil && policy.BearerTokenFormat != nil {
		bearerTokenFormat = *policy.BearerTokenFormat
	}

	if auth := r.Header.Get(httputil.HeaderAuthorization); auth != "" {
		prefix := "Bearer "
		if strings.HasPrefix(strings.ToLower(auth), strings.ToLower(prefix)) &&
			bearerTokenFormat == BearerTokenFormatIDPAccessToken {
			return auth[len(prefix):], true
		}
	}

	return "", false
}

// GetIncomingIDPAccessTokenForPolicy returns the raw idp identity token from a request if there is one.
func (cfg *Config) GetIncomingIDPIdentityTokenForPolicy(policy *Policy, r *http.Request) (rawIdentityToken string, ok bool) {
	bearerTokenFormat := BearerTokenFormatDefault
	if cfg.Options != nil && cfg.Options.BearerTokenFormat != nil {
		bearerTokenFormat = *cfg.Options.BearerTokenFormat
	}
	if policy != nil && policy.BearerTokenFormat != nil {
		bearerTokenFormat = *policy.BearerTokenFormat
	}

	if auth := r.Header.Get(httputil.HeaderAuthorization); auth != "" {
		prefix := "Bearer "
		if strings.HasPrefix(strings.ToLower(auth), strings.ToLower(prefix)) &&
			bearerTokenFormat == BearerTokenFormatIDPIdentityToken {
			return auth[len(prefix):], true
		}
	}

	return "", false
}

var accessTokenUUIDNamespace = uuid.MustParse("0194f6f8-e760-76a0-8917-e28ac927a34d")

func getAccessTokenSessionID(idp *identitypb.Provider, rawAccessToken string) string {
	namespace := accessTokenUUIDNamespace
	// make the session ID per-idp settings
	if idp != nil {
		namespace = uuid.NewSHA1(namespace, []byte(idp.GetId()))
	}
	return uuid.NewSHA1(namespace, []byte(rawAccessToken)).String()
}

var identityTokenUUIDNamespace = uuid.MustParse("0194f6f9-aec0-704e-bb4a-51054f17ad17")

func getIdentityTokenSessionID(idp *identitypb.Provider, rawIdentityToken string) string {
	namespace := identityTokenUUIDNamespace
	// make the session ID per-idp settings
	if idp != nil {
		namespace = uuid.NewSHA1(namespace, []byte(idp.GetId()))
	}
	return uuid.NewSHA1(namespace, []byte(rawIdentityToken)).String()
}
