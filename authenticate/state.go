package authenticate

import (
	"context"
	"crypto/cipher"
	"fmt"
	"net/http"
	"net/url"

	"github.com/go-jose/go-jose/v3"
	oteltrace "go.opentelemetry.io/otel/trace"
	"golang.org/x/oauth2"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/authenticateflow"
	"github.com/pomerium/pomerium/internal/encoding"
	"github.com/pomerium/pomerium/internal/encoding/jws"
	"github.com/pomerium/pomerium/internal/handlers"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/internal/sessions/cookie"
	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/identity"
)

type flow interface {
	VerifyAuthenticateSignature(r *http.Request) error
	SignIn(w http.ResponseWriter, r *http.Request, sessionState *sessions.State) error
	PersistSession(ctx context.Context, w http.ResponseWriter, sessionState *sessions.State, claims identity.SessionClaims, accessToken *oauth2.Token) error
	VerifySession(ctx context.Context, r *http.Request, sessionState *sessions.State) error
	RevokeSession(ctx context.Context, r *http.Request, authenticator identity.Authenticator, sessionState *sessions.State) string
	GetUserInfoData(r *http.Request, sessionState *sessions.State) handlers.UserInfoData
	LogAuthenticateEvent(r *http.Request)
	DecryptURLValues(url.Values) (url.Values, error)

	SignInPendingSession(w http.ResponseWriter, r *http.Request) error
	GetPendingSession(ctx context.Context, pendingSessionId string) (*session.PendingSession, error)
	DeletePendingSession(ctx context.Context, pendingSessionId string) error
}

type authenticateState struct {
	flow flow

	redirectURL *url.URL
	// sharedEncoder is the encoder to use to serialize data to be consumed
	// by other services
	sharedEncoder encoding.MarshalUnmarshaler
	// sharedKey is the secret to encrypt and authenticate data shared between services
	sharedKey []byte
	// sharedCipher is the cipher to use to encrypt/decrypt data shared between services
	sharedCipher cipher.AEAD
	// cookieSecret is the secret to encrypt and authenticate session data
	cookieSecret []byte
	// cookieCipher is the cipher to use to encrypt/decrypt session data
	cookieCipher cipher.AEAD
	// sessionStore is the session store used to persist a user's session
	sessionStore sessions.SessionStore
	// sessionLoaders are a collection of session loaders to attempt to pull
	// a user's session state from
	sessionLoader sessions.SessionLoader

	jwk *jose.JSONWebKeySet
}

func newAuthenticateState() *authenticateState {
	return &authenticateState{
		jwk: new(jose.JSONWebKeySet),
	}
}

func newAuthenticateStateFromConfig(
	ctx context.Context,
	tracerProvider oteltrace.TracerProvider,
	cfg *config.Config,
	authenticateConfig *authenticateConfig,
) (*authenticateState, error) {
	err := ValidateOptions(cfg.Options)
	if err != nil {
		return nil, err
	}

	state := &authenticateState{}

	authenticateURL, err := cfg.Options.GetAuthenticateURL()
	if err != nil {
		return nil, err
	}

	state.redirectURL, err = urlutil.DeepCopy(authenticateURL)
	if err != nil {
		return nil, err
	}

	state.redirectURL.Path = cfg.Options.AuthenticateCallbackPath

	// shared cipher to encrypt data before passing data between services
	state.sharedKey, err = cfg.Options.GetSharedKey()
	if err != nil {
		return nil, err
	}

	state.sharedCipher, err = cryptutil.NewAEADCipher(state.sharedKey)
	if err != nil {
		return nil, err
	}

	// shared state encoder setup
	state.sharedEncoder, err = jws.NewHS256Signer(state.sharedKey)
	if err != nil {
		return nil, err
	}

	// private state encoder setup, used to encrypt oauth2 tokens
	state.cookieSecret, err = cfg.Options.GetCookieSecret()
	if err != nil {
		return nil, err
	}

	state.cookieCipher, err = cryptutil.NewAEADCipher(state.cookieSecret)
	if err != nil {
		return nil, err
	}

	cookieStore, err := cookie.NewStore(func() cookie.Options {
		return cookie.Options{
			Name:     cfg.Options.CookieName + "_authenticate",
			Domain:   cfg.Options.CookieDomain,
			Secure:   true,
			HTTPOnly: cfg.Options.CookieHTTPOnly,
			Expire:   cfg.Options.CookieExpire,
			SameSite: cfg.Options.GetCookieSameSite(),
		}
	}, state.sharedEncoder)
	if err != nil {
		return nil, err
	}

	state.sessionStore = cookieStore
	state.sessionLoader = cookieStore
	state.jwk = new(jose.JSONWebKeySet)
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
			state.jwk.Keys = append(state.jwk.Keys, *k)
		}
	}

	if cfg.Options.UseStatelessAuthenticateFlow() {
		state.flow, err = authenticateflow.NewStateless(ctx,
			tracerProvider,
			cfg,
			cookieStore,
			authenticateConfig.getIdentityProvider,
			authenticateConfig.profileTrimFn,
			authenticateConfig.authEventFn,
		)
	} else {
		state.flow, err = authenticateflow.NewStateful(ctx, tracerProvider, cfg, cookieStore)
	}
	if err != nil {
		return nil, err
	}

	return state, nil
}
