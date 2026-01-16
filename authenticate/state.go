package authenticate

import (
	"context"
	"crypto/cipher"
	"fmt"
	"net/http"
	"net/url"

	oteltrace "go.opentelemetry.io/otel/trace"
	"golang.org/x/oauth2"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/authenticateflow"
	"github.com/pomerium/pomerium/internal/encoding/jws"
	"github.com/pomerium/pomerium/internal/handlers"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/internal/sessions/cookie"
	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	"github.com/pomerium/pomerium/pkg/endpoints"
	"github.com/pomerium/pomerium/pkg/grpc"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/identity"
)

type flow interface {
	VerifyAuthenticateSignature(r *http.Request) error
	SignIn(w http.ResponseWriter, r *http.Request, h *session.Handle) error
	PersistSession(ctx context.Context, w http.ResponseWriter, h *session.Handle, claims identity.SessionClaims, accessToken *oauth2.Token) error
	VerifySession(ctx context.Context, r *http.Request, h *session.Handle) error
	RevokeSession(ctx context.Context, r *http.Request, authenticator identity.Authenticator, h *session.Handle) string
	GetUserInfoData(r *http.Request, h *session.Handle) handlers.UserInfoData
	LogAuthenticateEvent(r *http.Request)
	GetIdentityProviderIDForURLValues(url.Values) string

	AuthenticatePendingSession(w http.ResponseWriter, r *http.Request, h *session.Handle) error
	GetSessionBindingInfo(w http.ResponseWriter, r *http.Request, h *session.Handle) error
	RevokeSessionBinding(w http.ResponseWriter, r *http.Request, h *session.Handle) error
	RevokeIdentityBinding(w http.ResponseWriter, r *http.Request, h *session.Handle) error
}

type authenticateState struct {
	flow flow

	redirectURL *url.URL
	// sharedKey is the secret to encrypt and authenticate data shared between services
	sharedKey []byte
	// cookieCipher is the cipher to use to encrypt/decrypt session data
	cookieCipher        cipher.AEAD
	sessionHandleReader sessions.HandleReader
	sessionHandleWriter sessions.HandleWriter

	csrf *csrfCookieValidation
}

func newAuthenticateStateFromConfig(
	ctx context.Context,
	tracerProvider oteltrace.TracerProvider,
	cfg *config.Config,
	authenticateConfig *authenticateConfig,
	outboundGrpcConn *grpc.CachedOutboundGRPClientConn,
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

	state.redirectURL.Path = endpoints.PathAuthenticateCallback

	// shared cipher to encrypt data before passing data between services
	state.sharedKey, err = cfg.Options.GetSharedKey()
	if err != nil {
		return nil, err
	}

	encoder, err := jws.NewHS256Signer(state.sharedKey)
	if err != nil {
		return nil, err
	}

	// private state encoder setup, used to encrypt oauth2 tokens
	cookieSecret, err := cfg.Options.GetCookieSecret()
	if err != nil {
		return nil, err
	}

	state.cookieCipher, err = cryptutil.NewAEADCipher(cookieSecret)
	if err != nil {
		return nil, err
	}

	cookieStore, err := cookie.New(func() cookie.Options {
		return cookie.Options{
			Name:     cfg.Options.CookieName + "_authenticate",
			Domain:   cfg.Options.CookieDomain,
			Secure:   true,
			HTTPOnly: cfg.Options.CookieHTTPOnly,
			Expire:   cfg.Options.CookieExpire,
			SameSite: cfg.Options.GetCookieSameSite(),
		}
	}, encoder)
	if err != nil {
		return nil, err
	}

	state.csrf = newCSRFCookieValidation(
		cookieSecret,
		fmt.Sprintf("%s_csrf", cfg.Options.CookieName),
		cfg.Options.GetCSRFSameSite(),
	)

	state.sessionHandleReader = cookieStore
	state.sessionHandleWriter = cookieStore

	if cfg.Options.UseStatelessAuthenticateFlow() {
		state.flow, err = authenticateflow.NewStateless(ctx,
			tracerProvider,
			cfg,
			cookieStore,
			authenticateConfig.getIdentityProvider,
			authenticateConfig.profileTrimFn,
			authenticateConfig.authEventFn,
			outboundGrpcConn,
		)
	} else {
		opts := []authenticateflow.StatefulFlowOption{}
		if authenticateConfig.sshSignHandler != nil {
			opts = append(opts, authenticateflow.WithSSHSignInHandler(authenticateConfig.sshSignHandler))
		}
		state.flow, err = authenticateflow.NewStateful(ctx, tracerProvider, cfg, cookieStore, outboundGrpcConn, opts...)
	}
	if err != nil {
		return nil, err
	}

	return state, nil
}
