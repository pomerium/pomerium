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

	"github.com/pomerium/pomerium/authenticate/providers"
	"github.com/pomerium/pomerium/internal/cryptutil"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/internal/templates"
)

var defaultOptions = &Options{
	CookieName:         "_pomerium_authenticate",
	CookieHTTPOnly:     true,
	CookieExpire:       time.Duration(168) * time.Hour,
	CookieRefresh:      time.Duration(1) * time.Hour,
	SessionLifetimeTTL: time.Duration(720) * time.Hour,
	Scopes:             []string{"openid", "email", "profile"},
}

// Options permits the configuration of the authentication service
type Options struct {
	RedirectURL *url.URL `envconfig:"REDIRECT_URL" ` // e.g. auth.example.com/oauth/callback

	SharedKey string `envconfig:"SHARED_SECRET"`

	// Coarse authorization based on user email domain
	AllowedDomains   []string `envconfig:"ALLOWED_DOMAINS"`
	ProxyRootDomains []string `envconfig:"PROXY_ROOT_DOMAIN"`

	// Session/Cookie management
	CookieName     string
	CookieSecret   string        `envconfig:"COOKIE_SECRET"`
	CookieDomain   string        `envconfig:"COOKIE_DOMAIN"`
	CookieExpire   time.Duration `envconfig:"COOKIE_EXPIRE"`
	CookieRefresh  time.Duration `envconfig:"COOKIE_REFRESH"`
	CookieSecure   bool          `envconfig:"COOKIE_SECURE"`
	CookieHTTPOnly bool          `envconfig:"COOKIE_HTTP_ONLY"`

	SessionLifetimeTTL time.Duration `envconfig:"SESSION_LIFETIME_TTL"`

	// Authentication provider configuration vars
	ClientID           string   `envconfig:"IDP_CLIENT_ID"`     // IdP ClientID
	ClientSecret       string   `envconfig:"IDP_CLIENT_SECRET"` // IdP Secret
	Provider           string   `envconfig:"IDP_PROVIDER"`      //Provider name e.g. "oidc","okta","google",etc
	ProviderURL        string   `envconfig:"IDP_PROVIDER_URL"`
	Scopes             []string `envconfig:"IDP_SCOPE" default:"openid,email,profile"`
	SkipProviderButton bool     `envconfig:"SKIP_PROVIDER_BUTTON"`
}

// OptionsFromEnvConfig builds the authentication service's configuration
// options from provided environmental variables
func OptionsFromEnvConfig() (*Options, error) {
	o := defaultOptions
	if err := envconfig.Process("", o); err != nil {
		return nil, err
	}
	return o, nil
}

// Validate checks to see if configuration values are valid for authentication service.
// The checks do not modify the internal state of the Option structure. Function returns
// on first error found.
func (o *Options) Validate() error {

	if o.RedirectURL == nil {
		return errors.New("missing setting: identity provider redirect url")
	}
	redirectPath := "/oauth2/callback"
	if o.RedirectURL.Path != redirectPath {
		return fmt.Errorf("setting redirect-url was %s path should be %s", o.RedirectURL.Path, redirectPath)
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

// Authenticate stores all the information associated with proxying the request.
type Authenticate struct {
	RedirectURL *url.URL

	Validator func(string) bool

	AllowedDomains   []string
	ProxyRootDomains []string
	CookieSecure     bool

	SharedKey string

	SessionLifetimeTTL time.Duration

	templates    *template.Template
	csrfStore    sessions.CSRFStore
	sessionStore sessions.SessionStore
	cipher       cryptutil.Cipher

	skipProviderButton bool

	provider providers.Provider
}

// New creates a Authenticate struct and applies the optional functions slice to the struct.
func New(opts *Options, optionFuncs ...func(*Authenticate) error) (*Authenticate, error) {
	if opts == nil {
		return nil, errors.New("options cannot be nil")
	}
	if err := opts.Validate(); err != nil {
		return nil, err
	}
	decodedAuthCodeSecret, err := base64.StdEncoding.DecodeString(opts.CookieSecret)
	if err != nil {
		return nil, err
	}
	cipher, err := cryptutil.NewCipher([]byte(decodedAuthCodeSecret))
	if err != nil {
		return nil, err
	}
	decodedCookieSecret, err := base64.StdEncoding.DecodeString(opts.CookieSecret)
	if err != nil {
		return nil, err
	}
	cookieStore, err := sessions.NewCookieStore(opts.CookieName,
		sessions.CreateMiscreantCookieCipher(decodedCookieSecret),
		func(c *sessions.CookieStore) error {
			c.CookieDomain = opts.CookieDomain
			c.CookieHTTPOnly = opts.CookieHTTPOnly
			c.CookieExpire = opts.CookieExpire
			c.CookieSecure = opts.CookieSecure
			return nil
		})

	if err != nil {
		return nil, err
	}

	p := &Authenticate{
		SharedKey:          opts.SharedKey,
		AllowedDomains:     opts.AllowedDomains,
		ProxyRootDomains:   dotPrependDomains(opts.ProxyRootDomains),
		CookieSecure:       opts.CookieSecure,
		RedirectURL:        opts.RedirectURL,
		templates:          templates.New(),
		csrfStore:          cookieStore,
		sessionStore:       cookieStore,
		cipher:             cipher,
		skipProviderButton: opts.SkipProviderButton,
	}
	// p.ServeMux = p.Handler()
	p.provider, err = newProvider(opts)
	if err != nil {
		return nil, err
	}

	// apply the option functions
	for _, optFunc := range optionFuncs {
		err := optFunc(p)
		if err != nil {
			return nil, err
		}
	}
	return p, nil
}

func newProvider(opts *Options) (providers.Provider, error) {
	pd := &providers.ProviderData{
		RedirectURL:        opts.RedirectURL,
		ProviderName:       opts.Provider,
		ProviderURL:        opts.ProviderURL,
		ClientID:           opts.ClientID,
		ClientSecret:       opts.ClientSecret,
		SessionLifetimeTTL: opts.SessionLifetimeTTL,
		Scopes:             opts.Scopes,
	}
	np, err := providers.New(opts.Provider, pd)
	if err != nil {
		return nil, err
	}
	return providers.NewSingleFlightProvider(np), nil

}

func dotPrependDomains(d []string) []string {
	for i := range d {
		if d[i] != "" && !strings.HasPrefix(d[i], ".") {
			d[i] = fmt.Sprintf(".%s", d[i])
		}
	}
	return d
}
