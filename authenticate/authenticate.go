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

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/cryptutil"
	"github.com/pomerium/pomerium/internal/encoding"
	"github.com/pomerium/pomerium/internal/encoding/ecjson"
	"github.com/pomerium/pomerium/internal/encoding/jws"
	"github.com/pomerium/pomerium/internal/frontend"
	"github.com/pomerium/pomerium/internal/grpc"
	"github.com/pomerium/pomerium/internal/grpc/cache/client"
	"github.com/pomerium/pomerium/internal/identity"
	"github.com/pomerium/pomerium/internal/identity/oauth"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/internal/sessions/cache"
	"github.com/pomerium/pomerium/internal/sessions/cookie"
	"github.com/pomerium/pomerium/internal/sessions/header"
	"github.com/pomerium/pomerium/internal/sessions/queryparam"
	"github.com/pomerium/pomerium/internal/urlutil"
)

// ValidateOptions checks that configuration are complete and valid.
// Returns on first error found.
func ValidateOptions(o config.Options) error {
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

	// provider is the interface to interacting with the identity provider (IdP)
	provider identity.Authenticator

	// cacheClient is the interface for setting and getting sessions from a cache
	cacheClient client.Cacher

	templates *template.Template
}

// New validates and creates a new authenticate service from a set of Options.
func New(opts config.Options) (*Authenticate, error) {
	if err := ValidateOptions(opts); err != nil {
		return nil, err
	}

	// shared state encoder setup
	sharedCipher, _ := cryptutil.NewAEADCipherFromBase64(opts.SharedKey)
	signedEncoder, err := jws.NewHS256Signer([]byte(opts.SharedKey), opts.AuthenticateURL.Host)
	if err != nil {
		return nil, err
	}

	// private state encoder setup
	decodedCookieSecret, _ := base64.StdEncoding.DecodeString(opts.CookieSecret)
	cookieCipher, _ := cryptutil.NewAEADCipher(decodedCookieSecret)
	encryptedEncoder := ecjson.New(cookieCipher)

	cookieOptions := &cookie.Options{
		Name:     opts.CookieName,
		Domain:   opts.CookieDomain,
		Secure:   opts.CookieSecure,
		HTTPOnly: opts.CookieHTTPOnly,
		Expire:   opts.CookieExpire,
	}

	cookieStore, err := cookie.NewStore(cookieOptions, encryptedEncoder)
	if err != nil {
		return nil, err
	}

	cacheConn, err := grpc.NewGRPCClientConn(
		&grpc.Options{
			Addr:                    opts.CacheURL,
			OverrideCertificateName: opts.OverrideCertificateName,
			CA:                      opts.CA,
			CAFile:                  opts.CAFile,
			RequestTimeout:          opts.GRPCClientTimeout,
			ClientDNSRoundRobin:     opts.GRPCClientDNSRoundRobin,
			WithInsecure:            opts.GRPCInsecure,
		})
	if err != nil {
		return nil, err
	}

	cacheClient := client.New(cacheConn)

	cacheStore := cache.NewStore(&cache.Options{
		Cache:        cacheClient,
		Encoder:      encryptedEncoder,
		QueryParam:   urlutil.QueryAccessTokenID,
		WrappedStore: cookieStore})

	qpStore := queryparam.NewStore(encryptedEncoder, "pomerium_programmatic_token")
	headerStore := header.NewStore(encryptedEncoder, "Pomerium")

	redirectURL, _ := urlutil.DeepCopy(opts.AuthenticateURL)
	redirectURL.Path = opts.AuthenticateCallbackPath
	// configure our identity provider
	provider, err := identity.NewAuthenticator(
		oauth.Options{
			RedirectURL:    redirectURL,
			ProviderName:   opts.Provider,
			ProviderURL:    opts.ProviderURL,
			ClientID:       opts.ClientID,
			ClientSecret:   opts.ClientSecret,
			Scopes:         opts.Scopes,
			ServiceAccount: opts.ServiceAccount,
		})

	if err != nil {
		return nil, err
	}

	return &Authenticate{
		RedirectURL: redirectURL,
		// shared state
		sharedKey:     opts.SharedKey,
		sharedCipher:  sharedCipher,
		sharedEncoder: signedEncoder,
		// private state
		cookieSecret:     decodedCookieSecret,
		cookieCipher:     cookieCipher,
		cookieOptions:    cookieOptions,
		sessionStore:     cacheStore,
		encryptedEncoder: encryptedEncoder,
		sessionLoaders:   []sessions.SessionLoader{cacheStore, qpStore, headerStore, cookieStore},
		// IdP
		provider: provider,
		// grpc client for cache
		cacheClient: cacheClient,

		templates: template.Must(frontend.NewTemplates()),
	}, nil
}
