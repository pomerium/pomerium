package authenticate

import (
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/pkg/identity"
	"github.com/pomerium/pomerium/pkg/identity/oauth"
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

	idp, err := options.GetIdentityProviderForID(idpID)
	if err != nil {
		return nil, err
	}
	o := oauth.Options{
		RedirectURL:     redirectURL,
		ProviderName:    idp.GetType(),
		ProviderURL:     idp.GetUrl(),
		ClientID:        idp.GetClientId(),
		ClientSecret:    idp.GetClientSecret(),
		Scopes:          idp.GetScopes(),
		AuthCodeOptions: idp.GetRequestParams(),
	}
	if v := idp.GetAccessTokenAllowedAudiences(); v != nil {
		o.AccessTokenAllowedAudiences = &v.Values
	}
	return identity.NewAuthenticator(o)
}
