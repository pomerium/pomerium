package authenticate

import (
	"crypto/cipher"
	"encoding/base64"
	"fmt"
	"net/url"
	"sync/atomic"

	"gopkg.in/square/go-jose.v2"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/encoding"
	"github.com/pomerium/pomerium/internal/encoding/ecjson"
	"github.com/pomerium/pomerium/internal/encoding/jws"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/internal/sessions/cookie"
	"github.com/pomerium/pomerium/internal/sessions/header"
	"github.com/pomerium/pomerium/internal/sessions/queryparam"
	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	"github.com/pomerium/pomerium/pkg/grpc"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/directory"
)

type authenticateState struct {
	redirectURL *url.URL
	// administrators keeps track of administrator users.
	administrators map[string]struct{}
	// sharedEncoder is the encoder to use to serialize data to be consumed
	// by other services
	sharedEncoder encoding.MarshalUnmarshaler
	// cookieSecret is the secret to encrypt and authenticate session data
	cookieSecret []byte
	// cookieCipher is the cipher to use to encrypt/decrypt session data
	cookieCipher cipher.AEAD
	// encryptedEncoder is the encoder used to marshal and unmarshal session data
	encryptedEncoder encoding.MarshalUnmarshaler
	// sessionStore is the session store used to persist a user's session
	sessionStore sessions.SessionStore
	// sessionLoaders are a collection of session loaders to attempt to pull
	// a user's session state from
	sessionLoaders []sessions.SessionLoader

	jwk *jose.JSONWebKeySet

	dataBrokerClient databroker.DataBrokerServiceClient
	directoryClient  directory.DirectoryServiceClient
}

func newAuthenticateState() *authenticateState {
	return &authenticateState{
		administrators: map[string]struct{}{},
		jwk:            new(jose.JSONWebKeySet),
	}
}

func newAuthenticateStateFromConfig(cfg *config.Config) (*authenticateState, error) {
	err := ValidateOptions(cfg.Options)
	if err != nil {
		return nil, err
	}

	state := &authenticateState{}

	state.redirectURL, _ = urlutil.DeepCopy(cfg.Options.AuthenticateURL)
	state.redirectURL.Path = cfg.Options.AuthenticateCallbackPath

	state.administrators = make(map[string]struct{}, len(cfg.Options.Administrators))
	for _, admin := range cfg.Options.Administrators {
		state.administrators[admin] = struct{}{}
	}

	// shared state encoder setup
	state.sharedEncoder, err = jws.NewHS256Signer([]byte(cfg.Options.SharedKey), cfg.Options.GetAuthenticateURL().Host)
	if err != nil {
		return nil, err
	}

	// private state encoder setup, used to encrypt oauth2 tokens
	state.cookieSecret, _ = base64.StdEncoding.DecodeString(cfg.Options.CookieSecret)
	state.cookieCipher, _ = cryptutil.NewAEADCipher(state.cookieSecret)
	state.encryptedEncoder = ecjson.New(state.cookieCipher)

	qpStore := queryparam.NewStore(state.encryptedEncoder, urlutil.QueryProgrammaticToken)
	headerStore := header.NewStore(state.encryptedEncoder, httputil.AuthorizationTypePomerium)

	cookieStore, err := cookie.NewStore(func() cookie.Options {
		return cookie.Options{
			Name:     cfg.Options.CookieName,
			Domain:   cfg.Options.CookieDomain,
			Secure:   cfg.Options.CookieSecure,
			HTTPOnly: cfg.Options.CookieHTTPOnly,
			Expire:   cfg.Options.CookieExpire,
		}
	}, state.sharedEncoder)
	if err != nil {
		return nil, err
	}

	state.sessionStore = cookieStore
	state.sessionLoaders = []sessions.SessionLoader{qpStore, headerStore, cookieStore}

	state.jwk = new(jose.JSONWebKeySet)
	if cfg.Options.SigningKey != "" {
		decodedCert, err := base64.StdEncoding.DecodeString(cfg.Options.SigningKey)
		if err != nil {
			return nil, fmt.Errorf("authenticate: failed to decode signing key: %w", err)
		}
		jwk, err := cryptutil.PublicJWKFromBytes(decodedCert, jose.ES256)
		if err != nil {
			return nil, fmt.Errorf("authenticate: failed to convert jwks: %w", err)
		}
		state.jwk.Keys = append(state.jwk.Keys, *jwk)
	}

	dataBrokerConn, err := grpc.GetGRPCClientConn("databroker", &grpc.Options{
		Addr:                    cfg.Options.DataBrokerURL,
		OverrideCertificateName: cfg.Options.OverrideCertificateName,
		CA:                      cfg.Options.CA,
		CAFile:                  cfg.Options.CAFile,
		RequestTimeout:          cfg.Options.GRPCClientTimeout,
		ClientDNSRoundRobin:     cfg.Options.GRPCClientDNSRoundRobin,
		WithInsecure:            cfg.Options.GRPCInsecure,
		ServiceName:             cfg.Options.Services,
	})
	if err != nil {
		return nil, err
	}

	state.dataBrokerClient = databroker.NewDataBrokerServiceClient(dataBrokerConn)
	state.directoryClient = directory.NewDirectoryServiceClient(dataBrokerConn)

	return state, nil
}

type atomicAuthenticateState struct {
	atomic.Value
}

func newAtomicAuthenticateState(state *authenticateState) *atomicAuthenticateState {
	aas := new(atomicAuthenticateState)
	aas.Store(state)
	return aas
}

func (aas *atomicAuthenticateState) Load() *authenticateState {
	return aas.Value.Load().(*authenticateState)
}

func (aas *atomicAuthenticateState) Store(state *authenticateState) {
	aas.Value.Store(state)
}
