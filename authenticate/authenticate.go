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
	"github.com/pomerium/pomerium/internal/urlutil"
)

// ValidateOptions checks that configuration are complete and valid.
// Returns on first error found.
func ValidateOptions(o config.Options) error {
	if _, err := cryptutil.NewCipherFromBase64(o.SharedKey); err != nil {
		return fmt.Errorf("authenticate: 'SHARED_SECRET' invalid: %v", err)
	}
	if _, err := cryptutil.NewCipherFromBase64(o.CookieSecret); err != nil {
		return fmt.Errorf("authenticate: 'COOKIE_SECRET' invalid %v", err)
	}
	if o.AuthenticateURL == nil {
		return errors.New("authenticate: 'AUTHENTICATE_SERVICE_URL' is required")
	}
	if _, err := urlutil.ParseAndValidateURL(o.AuthenticateURL.String()); err != nil {
		return fmt.Errorf("authenticate: couldn't parse 'AUTHENTICATE_SERVICE_URL': %v", err)
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

	templates    *template.Template
	csrfStore    sessions.CSRFStore
	sessionStore sessions.SessionStore
	cipher       cryptutil.Cipher
	provider     identity.Authenticator
}

// New validates and creates a new authenticate service from a set of Options.
func New(opts config.Options) (*Authenticate, error) {
	if err := ValidateOptions(opts); err != nil {
		return nil, err
	}
	decodedCookieSecret, _ := base64.StdEncoding.DecodeString(opts.CookieSecret)
	cipher, err := cryptutil.NewCipher(decodedCookieSecret)
	if err != nil {
		return nil, err
	}
	cookieStore, err := sessions.NewCookieStore(
		&sessions.CookieStoreOptions{
			Name:           opts.CookieName,
			CookieDomain:   opts.CookieDomain,
			CookieSecure:   opts.CookieSecure,
			CookieHTTPOnly: opts.CookieHTTPOnly,
			CookieExpire:   opts.CookieExpire,
			CookieCipher:   cipher,
		})
	if err != nil {
		return nil, err
	}
	redirectURL, _ := urlutil.DeepCopy(opts.AuthenticateURL)
	redirectURL.Path = "/oauth2/callback"
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
		csrfStore:    cookieStore,
		sessionStore: cookieStore,
		cipher:       cipher,
		provider:     provider,
	}, nil
}
