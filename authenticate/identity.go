package authenticate

import (
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/identity"
	"github.com/pomerium/pomerium/internal/identity/oauth"
	"github.com/pomerium/pomerium/internal/urlutil"
)

func defaultGetIdentityProvider(options *config.Options, idpID string) (identity.Authenticator, error) {
	authenticateURL, err := options.GetAuthenticateURL()
	if err != nil {
		return nil, err
	}

	redirectURL, err := urlutil.DeepCopy(authenticateURL)
	if err != nil {
		return nil, err
	}
	redirectURL.Path = options.AuthenticateCallbackPath

	return identity.NewAuthenticator(oauth.Options{
		RedirectURL:     redirectURL,
		ProviderName:    options.Provider,
		ProviderURL:     options.ProviderURL,
		ClientID:        options.ClientID,
		ClientSecret:    options.ClientSecret,
		Scopes:          options.Scopes,
		ServiceAccount:  options.ServiceAccount,
		AuthCodeOptions: options.RequestParams,
	})
}
