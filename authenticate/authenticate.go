// Package authenticate is a pomerium service that handles user authentication
// and refersh (AuthN).
package authenticate

import (
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"net/url"
	"sync"

	"gopkg.in/square/go-jose.v2"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/encoding"
	"github.com/pomerium/pomerium/internal/encoding/ecjson"
	"github.com/pomerium/pomerium/internal/encoding/jws"
	"github.com/pomerium/pomerium/internal/frontend"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/identity"
	"github.com/pomerium/pomerium/internal/identity/oauth"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/internal/sessions/cookie"
	"github.com/pomerium/pomerium/internal/sessions/header"
	"github.com/pomerium/pomerium/internal/sessions/queryparam"
	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	"github.com/pomerium/pomerium/pkg/grpc"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
)

// ValidateOptions checks that configuration are complete and valid.
// Returns on first error found.
func ValidateOptions(o *config.Options) error {
	if _, err := cryptutil.NewAEADCipherFromBase64(o.SharedKey); err != nil {
		return fmt.Errorf("authenticate: 'SHARED_SECRET' invalid: %w", err)
	}
	if _, err := cryptutil.NewAEADCipherFromBase64(o.CookieSecret); err != nil {
		return fmt.Errorf("authenticate: 'COOKIE_SECRET' invalid %w", err)
	}
	if err := urlutil.ValidateURL(o.AuthenticateURL); err != nil {
		return fmt.Errorf("authenticate: invalid 'AUTHENTICATE_SERVICE_URL': %w", err)
	}
	if o.Provider == "" {
		return errors.New("authenticate: 'IDP_PROVIDER' is required")
	}
	if o.ClientID == "" {
		return errors.New("authenticate: 'IDP_CLIENT_ID' is required")
	}
	if o.ClientSecret == "" {
		return errors.New("authenticate: 'IDP_CLIENT_SECRET' is required")
	}
	if o.AuthenticateCallbackPath == "" {
		return errors.New("authenticate: 'AUTHENTICATE_CALLBACK_PATH' is required")
	}
	if err := urlutil.ValidateURL(o.DataBrokerURL); err != nil {
		return fmt.Errorf("authenticate: invalid 'DATABROKER_SERVICE_URL': %w", err)
	}
	return nil
}

// Authenticate contains data required to run the authenticate service.
type Authenticate struct {
	// RedirectURL is the authenticate service's externally accessible
	// url that the identity provider (IdP) will callback to following
	// authentication flow
	RedirectURL *url.URL

	// values related to cross service communication
	//
	// sharedKey is used to encrypt and authenticate data between services
	sharedKey string
	// sharedCipher is used to encrypt data for use between services
	sharedCipher cipher.AEAD
	// sharedEncoder is the encoder to use to serialize data to be consumed
	// by other services
	sharedEncoder encoding.MarshalUnmarshaler

	// values related to user sessions
	//
	// cookieSecret is the secret to encrypt and authenticate session data
	cookieSecret []byte
	// cookieCipher is the cipher to use to encrypt/decrypt session data
	cookieCipher cipher.AEAD
	// encryptedEncoder is the encoder used to marshal and unmarshal session data
	encryptedEncoder encoding.MarshalUnmarshaler
	// sessionStore is the session store used to persist a user's session
	sessionStore  sessions.SessionStore
	cookieOptions *cookie.Options

	// sessionLoaders are a collection of session loaders to attempt to pull
	// a user's session state from
	sessionLoaders []sessions.SessionLoader

	// dataBrokerClient is used to retrieve sessions
	dataBrokerClient databroker.DataBrokerServiceClient

	// guard administrator below.
	administratorMu sync.Mutex
	// administrators keeps track of administrator users.
	administrator map[string]struct{}

	jwk *jose.JSONWebKeySet

	templates *template.Template

	options  *config.AtomicOptions
	provider *identity.AtomicAuthenticator
}

// New validates and creates a new authenticate service from a set of Options.
func New(cfg *config.Config) (*Authenticate, error) {
	if err := ValidateOptions(cfg.Options); err != nil {
		return nil, err
	}

	// shared state encoder setup
	sharedCipher, _ := cryptutil.NewAEADCipherFromBase64(cfg.Options.SharedKey)
	sharedEncoder, err := jws.NewHS256Signer([]byte(cfg.Options.SharedKey), cfg.Options.GetAuthenticateURL().Host)
	if err != nil {
		return nil, err
	}

	// private state encoder setup, used to encrypt oauth2 tokens
	decodedCookieSecret, _ := base64.StdEncoding.DecodeString(cfg.Options.CookieSecret)
	cookieCipher, _ := cryptutil.NewAEADCipher(decodedCookieSecret)
	encryptedEncoder := ecjson.New(cookieCipher)

	cookieOptions := &cookie.Options{
		Name:     cfg.Options.CookieName,
		Domain:   cfg.Options.CookieDomain,
		Secure:   cfg.Options.CookieSecure,
		HTTPOnly: cfg.Options.CookieHTTPOnly,
		Expire:   cfg.Options.CookieExpire,
	}

	dataBrokerConn, err := grpc.NewGRPCClientConn(
		&grpc.Options{
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

	dataBrokerClient := databroker.NewDataBrokerServiceClient(dataBrokerConn)

	qpStore := queryparam.NewStore(encryptedEncoder, urlutil.QueryProgrammaticToken)
	headerStore := header.NewStore(encryptedEncoder, httputil.AuthorizationTypePomerium)

	redirectURL, _ := urlutil.DeepCopy(cfg.Options.AuthenticateURL)
	redirectURL.Path = cfg.Options.AuthenticateCallbackPath

	if err != nil {
		return nil, err
	}

	a := &Authenticate{
		RedirectURL: redirectURL,
		// shared state
		sharedKey:     cfg.Options.SharedKey,
		sharedCipher:  sharedCipher,
		sharedEncoder: sharedEncoder,
		// private state
		cookieSecret:     decodedCookieSecret,
		cookieCipher:     cookieCipher,
		cookieOptions:    cookieOptions,
		encryptedEncoder: encryptedEncoder,
		// grpc client for cache
		dataBrokerClient: dataBrokerClient,
		jwk:              &jose.JSONWebKeySet{},
		templates:        template.Must(frontend.NewTemplates()),
		options:          config.NewAtomicOptions(),
		provider:         identity.NewAtomicAuthenticator(),
	}

	err = a.updateProvider(cfg)
	if err != nil {
		return nil, err
	}

	cookieStore, err := cookie.NewStore(func() cookie.Options {
		opts := a.options.Load()
		return cookie.Options{
			Name:     opts.CookieName,
			Domain:   opts.CookieDomain,
			Secure:   opts.CookieSecure,
			HTTPOnly: opts.CookieHTTPOnly,
			Expire:   opts.CookieExpire,
		}
	}, sharedEncoder)
	if err != nil {
		return nil, err
	}

	a.sessionStore = cookieStore
	a.sessionLoaders = []sessions.SessionLoader{qpStore, headerStore, cookieStore}

	if cfg.Options.SigningKey != "" {
		decodedCert, err := base64.StdEncoding.DecodeString(cfg.Options.SigningKey)
		if err != nil {
			return nil, fmt.Errorf("authenticate: failed to decode signing key: %w", err)
		}
		jwk, err := cryptutil.PublicJWKFromBytes(decodedCert, jose.ES256)
		if err != nil {
			return nil, fmt.Errorf("authenticate: failed to convert jwks: %w", err)
		}
		a.jwk.Keys = append(a.jwk.Keys, *jwk)
	}

	return a, nil
}

func (a *Authenticate) setAdminUsers(opts *config.Options) {
	a.administratorMu.Lock()
	defer a.administratorMu.Unlock()

	a.administrator = make(map[string]struct{}, len(opts.Administrators))
	for _, admin := range opts.Administrators {
		a.administrator[admin] = struct{}{}
	}
}

// OnConfigChange updates internal structures based on config.Options
func (a *Authenticate) OnConfigChange(cfg *config.Config) {
	if a == nil {
		return
	}

	log.Info().Str("checksum", fmt.Sprintf("%x", cfg.Options.Checksum())).Msg("authenticate: updating options")
	a.options.Store(cfg.Options)
	a.setAdminUsers(cfg.Options)
	if err := a.updateProvider(cfg); err != nil {
		log.Error().Err(err).Msg("authenticate: failed to update identity provider")
	}
}

func (a *Authenticate) updateProvider(cfg *config.Config) error {
	redirectURL, _ := urlutil.DeepCopy(cfg.Options.AuthenticateURL)
	redirectURL.Path = cfg.Options.AuthenticateCallbackPath

	// configure our identity provider
	provider, err := identity.NewAuthenticator(
		oauth.Options{
			RedirectURL:     redirectURL,
			ProviderName:    cfg.Options.Provider,
			ProviderURL:     cfg.Options.ProviderURL,
			ClientID:        cfg.Options.ClientID,
			ClientSecret:    cfg.Options.ClientSecret,
			Scopes:          cfg.Options.Scopes,
			ServiceAccount:  cfg.Options.ServiceAccount,
			AuthCodeOptions: cfg.Options.RequestParams,
		})
	if err != nil {
		return err
	}
	a.provider.Store(provider)

	return nil
}
