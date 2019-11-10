package authenticate // import "github.com/pomerium/pomerium/authenticate"

import (
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"net/url"
	"time"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/cryptutil"
	"github.com/pomerium/pomerium/internal/encoding"
	"github.com/pomerium/pomerium/internal/encoding/ecjson"
	"github.com/pomerium/pomerium/internal/encoding/jws"
	"github.com/pomerium/pomerium/internal/identity"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/internal/templates"
	"github.com/pomerium/pomerium/internal/urlutil"
)

const callbackPath = "/oauth2/callback"

// DefaultSessionDuration is the default time a managed route session is
// valid for.
var DefaultSessionDuration = time.Minute * 10

// ValidateOptions checks that configuration are complete and valid.
// Returns on first error found.
func ValidateOptions(o config.Options) error {
	if _, err := cryptutil.NewAEADCipherFromBase64(o.SharedKey); err != nil {
		return fmt.Errorf("authenticate: 'SHARED_SECRET' invalid: %v", err)
	}
	if _, err := cryptutil.NewAEADCipherFromBase64(o.CookieSecret); err != nil {
		return fmt.Errorf("authenticate: 'COOKIE_SECRET' invalid %v", err)
	}
	if err := urlutil.ValidateURL(o.AuthenticateURL); err != nil {
		return fmt.Errorf("authenticate: invalid 'AUTHENTICATE_SERVICE_URL': %v", err)
	}
	if o.ClientID == "" {
		return errors.New("authenticate: 'IDP_CLIENT_ID' is required")
	}
	if o.ClientSecret == "" {
		return errors.New("authenticate: 'IDP_CLIENT_SECRET' is required")
	}
	return nil
}

// Authenticate contains data required to run the authenticate service.
type Authenticate struct {
	// RedirectURL is the authenticate service's externally accessible
	// url that the identity provider (IdP) will callback to following
	// authentication flow
	RedirectURL *url.URL

	// sharedKey is used to encrypt and authenticate data between services
	sharedKey string
	// sharedCipher is used to encrypt data for use between services
	sharedCipher cipher.AEAD
	// sharedEncoder is the encoder to use to serialize data to be consumed
	// by other services
	sharedEncoder encoding.MarshalUnmarshaler

	// data related to this service only
	cookieOptions *sessions.CookieOptions
	// cookieSecret is the secret to encrypt and authenticate data for this service
	cookieSecret []byte
	// is the cipher to use to encrypt data for this service
	cookieCipher     cipher.AEAD
	sessionStore     sessions.SessionStore
	encryptedEncoder encoding.MarshalUnmarshaler
	sessionStores    []sessions.SessionStore
	sessionLoaders   []sessions.SessionLoader

	// provider is the interface to interacting with the identity provider (IdP)
	provider identity.Authenticator

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

	cookieOptions := &sessions.CookieOptions{
		Name:     opts.CookieName,
		Domain:   opts.CookieDomain,
		Secure:   opts.CookieSecure,
		HTTPOnly: opts.CookieHTTPOnly,
		Expire:   opts.CookieExpire,
	}

	cookieStore, err := sessions.NewCookieStore(cookieOptions, encryptedEncoder)
	if err != nil {
		return nil, err
	}
	qpStore := sessions.NewQueryParamStore(encryptedEncoder, "pomerium_programmatic_token")
	headerStore := sessions.NewHeaderStore(encryptedEncoder, "Pomerium")

	redirectURL, _ := urlutil.DeepCopy(opts.AuthenticateURL)
	redirectURL.Path = callbackPath
	// configure our identity provider
	provider, err := identity.New(
		opts.Provider,
		&identity.Provider{
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
		sessionStore:     cookieStore,
		encryptedEncoder: encryptedEncoder,
		sessionLoaders:   []sessions.SessionLoader{qpStore, headerStore, cookieStore},
		sessionStores:    []sessions.SessionStore{cookieStore, qpStore},
		// IdP
		provider: provider,

		templates: templates.New(),
	}, nil
}
