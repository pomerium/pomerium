package authenticate // import "github.com/pomerium/pomerium/authenticate"

import (
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"net/url"
	"strings"
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
	// SharedKey is used to authenticate requests between services
	SharedKey string `envconfig:"SHARED_SECRET"`

	// RedirectURL specifies the callback url following third party authentication
	RedirectURL *url.URL `envconfig:"REDIRECT_URL"`

	// Coarse authorization based on user email domain
	// todo(bdd) : to be replaced with authorization module
	AllowedDomains   []string `envconfig:"ALLOWED_DOMAINS"`
	ProxyRootDomains []string `envconfig:"PROXY_ROOT_DOMAIN"`

	// Session/Cookie management
	// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie
	CookieName     string
	CookieSecret   string        `envconfig:"COOKIE_SECRET"`
	CookieDomain   string        `envconfig:"COOKIE_DOMAIN"`
	CookieSecure   bool          `envconfig:"COOKIE_SECURE"`
	CookieHTTPOnly bool          `envconfig:"COOKIE_HTTP_ONLY"`
	CookieExpire   time.Duration `envconfig:"COOKIE_EXPIRE"`
	CookieRefresh  time.Duration `envconfig:"COOKIE_REFRESH"`

	// IdentityProvider provider configuration variables as specified by RFC6749
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
	if o.RedirectURL == nil {
		return errors.New("missing setting: identity provider redirect url")
	}
	redirectPath := "/oauth2/callback"
	if o.RedirectURL.Path != redirectPath {
		return fmt.Errorf("`setting` redirect-url was %s path should be %s", o.RedirectURL.Path, redirectPath)
	}
	if o.ClientID == "" {
		return errors.New("missing setting: client id")
	}
	if o.ClientSecret == "" {
		return errors.New("missing setting: client secret")
	}
	if len(o.AllowedDomains) == 0 {
		return errors.New("missing setting email domain")
	}
	if len(o.ProxyRootDomains) == 0 {
		return errors.New("missing setting: proxy root domain")
	}
	if o.SharedKey == "" {
		return errors.New("missing setting: shared secret")
	}
	decodedCookieSecret, err := base64.StdEncoding.DecodeString(o.CookieSecret)
	if err != nil {
		return fmt.Errorf("cookie secret is invalid base64: %v", err)
	}
	if len(decodedCookieSecret) != 32 {
		return fmt.Errorf("cookie secret expects 32 bytes but got %d", len(decodedCookieSecret))
	}
	return nil
}

// Authenticate validates a user's identity
type Authenticate struct {
	SharedKey string

	RedirectURL      *url.URL
	AllowedDomains   []string
	ProxyRootDomains []string

	Validator func(string) bool

	templates    *template.Template
	csrfStore    sessions.CSRFStore
	sessionStore sessions.SessionStore
	cipher       cryptutil.Cipher

	provider identity.Authenticator
}

// New validates and creates a new authenticate service from a set of Options
func New(opts *Options, optionFuncs ...func(*Authenticate) error) (*Authenticate, error) {
	if opts == nil {
		return nil, errors.New("options cannot be nil")
	}
	if err := opts.Validate(); err != nil {
		return nil, err
	}
	// checked by validate
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

	provider, err := identity.New(
		opts.Provider,
		&identity.Provider{
			RedirectURL:    opts.RedirectURL,
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

	p := &Authenticate{
		SharedKey:        opts.SharedKey,
		RedirectURL:      opts.RedirectURL,
		AllowedDomains:   opts.AllowedDomains,
		ProxyRootDomains: dotPrependDomains(opts.ProxyRootDomains),

		templates:    templates.New(),
		csrfStore:    cookieStore,
		sessionStore: cookieStore,
		cipher:       cipher,
		provider:     provider,
	}

	// validation via dependency injected function
	for _, optFunc := range optionFuncs {
		err := optFunc(p)
		if err != nil {
			return nil, err
		}
	}

	return p, nil
}

func dotPrependDomains(d []string) []string {
	for i := range d {
		if d[i] != "" && !strings.HasPrefix(d[i], ".") {
			d[i] = fmt.Sprintf(".%s", d[i])
		}
	}
	return d
}
