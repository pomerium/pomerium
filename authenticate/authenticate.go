package authenticate // import "github.com/pomerium/pomerium/authenticate"

import (
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
)

// ValidateOptions checks to see if configuration values are valid for the authenticate service.
// The checks do not modify the internal state of the Option structure. Returns
// on first error found.
func ValidateOptions(o config.Options) error {
	if o.AuthenticateURL.Hostname() == "" {
		return errors.New("authenticate: 'AUTHENTICATE_SERVICE_URL' missing")
	}
	if o.ClientID == "" {
		return errors.New("authenticate: 'IDP_CLIENT_ID' missing")
	}
	if o.ClientSecret == "" {
		return errors.New("authenticate: 'IDP_CLIENT_SECRET' missing")
	}
	if o.SharedKey == "" {
		return errors.New("authenticate: 'SHARED_SECRET' missing")
	}
	decodedCookieSecret, err := base64.StdEncoding.DecodeString(o.CookieSecret)
	if err != nil {
		return fmt.Errorf("authenticate: 'COOKIE_SECRET' must be base64 encoded: %v", err)
	}
	if len(decodedCookieSecret) != 32 {
		return fmt.Errorf("authenticate: 'COOKIE_SECRET' should be 32; got %d", len(decodedCookieSecret))
	}
	return nil
}

// Authenticate validates a user's identity
type Authenticate struct {
	SharedKey   string
	RedirectURL *url.URL

	templates    *template.Template
	csrfStore    sessions.CSRFStore
	sessionStore sessions.SessionStore
	restStore    sessions.SessionStore
	cipher       cryptutil.Cipher
	provider     identity.Authenticator
}

// New validates and creates a new authenticate service from a set of Options
func New(opts config.Options) (*Authenticate, error) {
	if err := ValidateOptions(opts); err != nil {
		return nil, err
	}
	decodedCookieSecret, _ := base64.StdEncoding.DecodeString(opts.CookieSecret)
	cipher, err := cryptutil.NewCipher([]byte(decodedCookieSecret))
	if err != nil {
		return nil, err
	}
	cookieStore, err := sessions.NewCookieStore(
		&sessions.CookieStoreOptions{
			Name:           opts.CookieName,
			CookieSecure:   opts.CookieSecure,
			CookieHTTPOnly: opts.CookieHTTPOnly,
			CookieExpire:   opts.CookieExpire,
			CookieCipher:   cipher,
		})
	if err != nil {
		return nil, err
	}
	redirectURL := opts.AuthenticateURL
	redirectURL.Path = "/oauth2/callback"
	provider, err := identity.New(
		opts.Provider,
		&identity.Provider{
			RedirectURL:    &redirectURL,
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
	restStore, err := sessions.NewRestStore(&sessions.RestStoreOptions{Cipher: cipher})
	if err != nil {
		return nil, err
	}
	return &Authenticate{
		SharedKey:    opts.SharedKey,
		RedirectURL:  &redirectURL,
		templates:    templates.New(),
		csrfStore:    cookieStore,
		sessionStore: cookieStore,
		restStore:    restStore,
		cipher:       cipher,
		provider:     provider,
	}, nil
}
