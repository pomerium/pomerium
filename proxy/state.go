package proxy

import (
	"context"
	"crypto/cipher"
	"net/http"
	"net/url"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/authenticateflow"
	"github.com/pomerium/pomerium/internal/encoding"
	"github.com/pomerium/pomerium/internal/encoding/jws"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/internal/sessions/cookie"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	"github.com/pomerium/pomerium/pkg/grpc"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
)

var outboundGRPCConnection = new(grpc.CachedOutboundGRPClientConn)

type authenticateFlow interface {
	AuthenticateSignInURL(ctx context.Context, queryParams url.Values, redirectURL *url.URL, idpID string) (string, error)
	AuthenticateDeviceCode(w http.ResponseWriter, r *http.Request, queryParams url.Values) error
	Callback(w http.ResponseWriter, r *http.Request) error
}

type proxyState struct {
	sharedKey    []byte
	sharedCipher cipher.AEAD

	authenticateURL          *url.URL
	authenticateDashboardURL *url.URL
	authenticateSigninURL    *url.URL
	authenticateRefreshURL   *url.URL

	encoder         encoding.MarshalUnmarshaler
	cookieSecret    []byte
	sessionStore    sessions.SessionStore
	jwtClaimHeaders config.JWTClaimHeaders

	dataBrokerClient databroker.DataBrokerServiceClient

	programmaticRedirectDomainWhitelist []string

	authenticateFlow authenticateFlow
}

func newProxyStateFromConfig(cfg *config.Config) (*proxyState, error) {
	err := ValidateOptions(cfg.Options)
	if err != nil {
		return nil, err
	}

	state := new(proxyState)

	state.sharedKey, err = cfg.Options.GetSharedKey()
	if err != nil {
		return nil, err
	}

	state.sharedCipher, err = cryptutil.NewAEADCipher(state.sharedKey)
	if err != nil {
		return nil, err
	}

	state.cookieSecret, err = cfg.Options.GetCookieSecret()
	if err != nil {
		return nil, err
	}

	// used to load and verify JWT tokens signed by the authenticate service
	state.encoder, err = jws.NewHS256Signer(state.sharedKey)
	if err != nil {
		return nil, err
	}

	state.jwtClaimHeaders = cfg.Options.JWTClaimsHeaders

	// errors checked in ValidateOptions
	state.authenticateURL, err = cfg.Options.GetAuthenticateURL()
	if err != nil {
		return nil, err
	}

	state.authenticateDashboardURL = state.authenticateURL.ResolveReference(&url.URL{Path: "/.pomerium/"})
	state.authenticateSigninURL = state.authenticateURL.ResolveReference(&url.URL{Path: signinURL})
	state.authenticateRefreshURL = state.authenticateURL.ResolveReference(&url.URL{Path: refreshURL})

	state.sessionStore, err = cookie.NewStore(func() cookie.Options {
		return cookie.Options{
			Name:     cfg.Options.CookieName,
			Domain:   cfg.Options.CookieDomain,
			Secure:   true,
			HTTPOnly: cfg.Options.CookieHTTPOnly,
			Expire:   cfg.Options.CookieExpire,
			SameSite: cfg.Options.GetCookieSameSite(),
		}
	}, state.encoder)
	if err != nil {
		return nil, err
	}

	dataBrokerConn, err := outboundGRPCConnection.Get(context.Background(), &grpc.OutboundOptions{
		OutboundPort:   cfg.OutboundPort,
		InstallationID: cfg.Options.InstallationID,
		ServiceName:    cfg.Options.Services,
		SignedJWTKey:   state.sharedKey,
	})
	if err != nil {
		return nil, err
	}

	state.dataBrokerClient = databroker.NewDataBrokerServiceClient(dataBrokerConn)

	state.programmaticRedirectDomainWhitelist = cfg.Options.ProgrammaticRedirectDomainWhitelist

	if cfg.Options.UseStatelessAuthenticateFlow() {
		state.authenticateFlow, err = authenticateflow.NewStateless(
			cfg, state.sessionStore, nil, nil, nil)
	} else {
		state.authenticateFlow, err = authenticateflow.NewStateful(cfg, state.sessionStore)
	}
	if err != nil {
		return nil, err
	}

	return state, nil
}
