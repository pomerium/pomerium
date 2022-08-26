package authenticate

import (
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/identity"
	"github.com/pomerium/pomerium/internal/identity/oauth"
	"github.com/pomerium/pomerium/internal/urlutil"
)

func defaultGetIdentityProvider(cfg *config.Config, idpID string) (identity.Authenticator, error) {
	authenticateURL, err := cfg.Options.GetAuthenticateURL()
	if err != nil {
		return nil, err
	}

	redirectURL, err := urlutil.DeepCopy(authenticateURL)
	if err != nil {
		return nil, err
	}
	redirectURL.Path = cfg.Options.AuthenticateCallbackPath

	idp, err := cfg.Options.GetIdentityProviderForID(idpID)
	if err != nil {
		return nil, err
	}
	return identity.NewAuthenticator(oauth.Options{
		RedirectURL:     redirectURL,
		ProviderName:    idp.GetType(),
		ProviderURL:     idp.GetUrl(),
		ClientID:        idp.GetClientId(),
		ClientSecret:    idp.GetClientSecret(),
		Scopes:          idp.GetScopes(),
		ServiceAccount:  idp.GetServiceAccount(),
		AuthCodeOptions: idp.GetRequestParams(),
	})
}
