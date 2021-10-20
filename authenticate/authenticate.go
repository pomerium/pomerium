// Package authenticate is a pomerium service that handles user authentication
// and refersh (AuthN).
package authenticate

import (
	"context"
	"errors"
	"fmt"
	"html/template"
	"net/url"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/frontend"
	"github.com/pomerium/pomerium/internal/identity"
	"github.com/pomerium/pomerium/internal/identity/oauth"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/pkg/cryptutil"
)

// ValidateOptions checks that configuration are complete and valid.
// Returns on first error found.
func ValidateOptions(o *config.Options) error {
	sharedKey, err := o.GetSharedKey()
	if err != nil {
		return fmt.Errorf("authenticate: 'SHARED_SECRET' invalid: %w", err)
	}
	if _, err := cryptutil.NewAEADCipher(sharedKey); err != nil {
		return fmt.Errorf("authenticate: 'SHARED_SECRET' invalid: %w", err)
	}
	if _, err := cryptutil.NewAEADCipherFromBase64(o.CookieSecret); err != nil {
		return fmt.Errorf("authenticate: 'COOKIE_SECRET' invalid %w", err)
	}
	if _, err := o.GetAuthenticateURL(); err != nil {
		return fmt.Errorf("authenticate: 'AUTHENTICATE_SERVICE_URL' invalid: %w", err)
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
	templates *template.Template

	options  *config.AtomicOptions
	provider *identity.AtomicAuthenticator
	state    *atomicAuthenticateState
}

// New validates and creates a new authenticate service from a set of Options.
func New(cfg *config.Config) (*Authenticate, error) {
	a := &Authenticate{
		templates: template.Must(frontend.NewTemplates()),
		options:   config.NewAtomicOptions(),
		provider:  identity.NewAtomicAuthenticator(),
		state:     newAtomicAuthenticateState(newAuthenticateState()),
	}

	state, err := newAuthenticateStateFromConfig(cfg)
	if err != nil {
		return nil, err
	}
	a.state.Store(state)

	err = a.updateProvider(cfg)
	if err != nil {
		return nil, err
	}

	return a, nil
}

// OnConfigChange updates internal structures based on config.Options
func (a *Authenticate) OnConfigChange(ctx context.Context, cfg *config.Config) {
	if a == nil {
		return
	}

	a.options.Store(cfg.Options)
	if state, err := newAuthenticateStateFromConfig(cfg); err != nil {
		log.Error(ctx).Err(err).Msg("authenticate: failed to update state")
	} else {
		a.state.Store(state)
	}
	if err := a.updateProvider(cfg); err != nil {
		log.Error(ctx).Err(err).Msg("authenticate: failed to update identity provider")
	}
}

func (a *Authenticate) updateProvider(cfg *config.Config) error {
	u, err := cfg.Options.GetAuthenticateURL()
	if err != nil {
		return err
	}

	redirectURL, _ := urlutil.DeepCopy(u)
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

func (a *Authenticate) getWebAuthnURL(values url.Values) (*url.URL, error) {
	uri, err := a.options.Load().GetAuthenticateURL()
	if err != nil {
		return nil, err
	}

	uri = uri.ResolveReference(&url.URL{
		Path: "/.pomerium/webauthn",
		RawQuery: buildURLValues(values, url.Values{
			urlutil.QueryDeviceType:      {"default"},
			urlutil.QueryEnrollmentToken: nil,
			urlutil.QueryRedirectURI: {uri.ResolveReference(&url.URL{
				Path: "/.pomerium/",
			}).String()},
		}).Encode(),
	})
	return urlutil.NewSignedURL(a.state.Load().sharedKey, uri).Sign(), nil
}

// buildURLValues creates a new url.Values map by traversing the keys in `defaults` and using the values
// from `values` if they exist, otherwise the provided defaults
func buildURLValues(values, defaults url.Values) url.Values {
	result := make(url.Values)
	for k, vs := range defaults {
		if values.Has(k) {
			result[k] = values[k]
		} else if vs != nil {
			result[k] = vs
		}
	}
	return result
}
