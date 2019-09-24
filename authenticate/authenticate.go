package authenticate // import "github.com/pomerium/pomerium/authenticate"

import (
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"net/url"

	"github.com/pomerium/pomerium/internal/config"
	"github.com/pomerium/pomerium/internal/cryptutil"
	"github.com/pomerium/pomerium/internal/identity"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/internal/templates"
	"github.com/pomerium/pomerium/internal/urlutil"
)

const callbackPath = "/oauth2/callback"

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
	SharedKey   string
	RedirectURL *url.URL

	cookieName   string
	cookieDomain string
	cookieSecret []byte
	templates    *template.Template
	sessionStore sessions.SessionStore
	cipher       cipher.AEAD
	encoder      cryptutil.SecureEncoder
	provider     identity.Authenticator
}

// New validates and creates a new authenticate service from a set of Options.
func New(opts config.Options) (*Authenticate, error) {
	if err := ValidateOptions(opts); err != nil {
		return nil, err
	}
	decodedCookieSecret, _ := base64.StdEncoding.DecodeString(opts.CookieSecret)
	cipher, err := cryptutil.NewAEADCipher(decodedCookieSecret)
	encoder := cryptutil.NewSecureJSONEncoder(cipher)
	if err != nil {
		return nil, err
	}
	if opts.CookieDomain == "" {
		opts.CookieDomain = sessions.ParentSubdomain(opts.AuthenticateURL.String())
	}
	cookieStore, err := sessions.NewCookieStore(
		&sessions.CookieStoreOptions{
			Name:           opts.CookieName,
			CookieDomain:   opts.CookieDomain,
			CookieSecure:   opts.CookieSecure,
			CookieHTTPOnly: opts.CookieHTTPOnly,
			CookieExpire:   opts.CookieExpire,
			Encoder:        encoder,
		})
	if err != nil {
		return nil, err
	}
	redirectURL, _ := urlutil.DeepCopy(opts.AuthenticateURL)
	redirectURL.Path = callbackPath
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
		SharedKey:    opts.SharedKey,
		RedirectURL:  redirectURL,
		templates:    templates.New(),
		sessionStore: cookieStore,
		cipher:       cipher,
		encoder:      encoder,
		provider:     provider,
		cookieSecret: decodedCookieSecret,
		cookieName:   opts.CookieName,
		cookieDomain: opts.CookieDomain,
	}, nil
}
