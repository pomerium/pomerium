package authenticate // import "github.com/pomerium/pomerium/authenticate"

import (
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"net/url"
	"time"

	"github.com/pomerium/envconfig"

	"github.com/pomerium/pomerium/internal/cryptutil"
	"github.com/pomerium/pomerium/internal/identity"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/internal/templates"
)

var defaultOptions = &Options{
	CookieName:     "_pomerium_authenticate",
	CookieHTTPOnly: true,
	CookieSecure:   true,
	CookieExpire:   time.Duration(14) * time.Hour,
	CookieRefresh:  time.Duration(30) * time.Minute,
}

// Options details the available configuration settings for the authenticate service
type Options struct {
	AuthenticateURL *url.URL `envconfig:"AUTHENTICATE_SERVICE_URL"`

	// SharedKey is used to authenticate requests between services
	SharedKey string `envconfig:"SHARED_SECRET"`
	// Session/Cookie management
	// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie
	CookieName     string
	CookieSecret   string        `envconfig:"COOKIE_SECRET"`
	CookieDomain   string        `envconfig:"COOKIE_DOMAIN"`
	CookieSecure   bool          `envconfig:"COOKIE_SECURE"`
	CookieHTTPOnly bool          `envconfig:"COOKIE_HTTP_ONLY"`
	CookieExpire   time.Duration `envconfig:"COOKIE_EXPIRE"`
	CookieRefresh  time.Duration `envconfig:"COOKIE_REFRESH"`

	// Identity provider configuration variables as specified by RFC6749
	// https://openid.net/specs/openid-connect-basic-1_0.html#RFC6749
	ClientID       string   `envconfig:"IDP_CLIENT_ID"`
	ClientSecret   string   `envconfig:"IDP_CLIENT_SECRET"`
	Provider       string   `envconfig:"IDP_PROVIDER"`
	ProviderURL    string   `envconfig:"IDP_PROVIDER_URL"`
	Scopes         []string `envconfig:"IDP_SCOPES"`
	ServiceAccount string   `envconfig:"IDP_SERVICE_ACCOUNT"`
}

// OptionsFromEnvConfig builds the authenticate service's configuration environmental variables
func OptionsFromEnvConfig() (*Options, error) {
	o := defaultOptions
	if err := envconfig.Process("", o); err != nil {
		return nil, err
	}
	return o, nil
}

// Validate checks to see if configuration values are valid for the authenticate service.
// The checks do not modify the internal state of the Option structure. Returns
// on first error found.
func (o *Options) Validate() error {
	if o.AuthenticateURL == nil {
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
	cipher       cryptutil.Cipher
	provider     identity.Authenticator
}

// New validates and creates a new authenticate service from a set of Options
func New(opts *Options) (*Authenticate, error) {
	if opts == nil {
		return nil, errors.New("authenticate: options cannot be nil")
	}
	if err := opts.Validate(); err != nil {
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
