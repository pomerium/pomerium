package proxy

import (
	"context"
	"crypto/cipher"
	"fmt"
	"net/url"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/encoding"
	"github.com/pomerium/pomerium/internal/encoding/jws"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/internal/sessions/cookie"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	"github.com/pomerium/pomerium/pkg/grpc"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/hpke"
)

var outboundGRPCConnection = new(grpc.CachedOutboundGRPClientConn)

type proxyState struct {
	sharedKey    []byte
	sharedCipher cipher.AEAD

	authenticateURL          *url.URL
	authenticateDashboardURL *url.URL
	authenticateSigninURL    *url.URL
	authenticateRefreshURL   *url.URL

	encoder                encoding.MarshalUnmarshaler
	cookieSecret           []byte
	sessionStore           sessions.SessionStore
	jwtClaimHeaders        config.JWTClaimHeaders
	hpkePrivateKey         *hpke.PrivateKey
	authenticateKeyFetcher hpke.KeyFetcher

	dataBrokerClient databroker.DataBrokerServiceClient

	programmaticRedirectDomainWhitelist []string
}

func newProxyStateFromConfig(cfg *config.Config) (*proxyState, error) {
	err := ValidateOptions(cfg.Options)
	if err != nil {
		return nil, err
	}

	state := new(proxyState)

	authenticateURL, err := cfg.Options.GetAuthenticateURL()
	if err != nil {
		return nil, err
	}

	state.sharedKey, err = cfg.Options.GetSharedKey()
	if err != nil {
		return nil, err
	}

	state.hpkePrivateKey, err = cfg.Options.GetHPKEPrivateKey()
	if err != nil {
		return nil, err
	}

	jwksURL := authenticateURL.ResolveReference(&url.URL{
		Path: "/.well-known/pomerium/jwks.json",
	}).String()
	transport := httputil.GetInsecureTransport()
	ok, err := cfg.WillHaveCertificateForServerName(authenticateURL.Hostname())
	if err != nil {
		return nil, fmt.Errorf("proxy: error determining if authenticate service will have a certificate name: %w", err)
	}
	if ok {
		transport, err = config.GetTLSClientTransport(cfg)
		if err != nil {
			return nil, fmt.Errorf("proxy: get tls client config: %w", err)
		}
	}
	state.authenticateKeyFetcher = hpke.NewKeyFetcher(jwksURL, transport)

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
			Secure:   cfg.Options.CookieSecure,
			HTTPOnly: cfg.Options.CookieHTTPOnly,
			Expire:   cfg.Options.CookieExpire,
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

	return state, nil
}
