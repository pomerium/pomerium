package authenticateflow

import (
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/urlutil"
	identitypb "github.com/pomerium/pomerium/pkg/grpc/identity"
	"github.com/pomerium/pomerium/pkg/identity"
	"github.com/pomerium/pomerium/pkg/identity/oauth"
)

func NewAuthenticator(options *config.Options, idp *identitypb.Provider) (identity.Authenticator, error) {
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
		ProviderName:    idp.GetType(),
		ProviderURL:     idp.GetUrl(),
		ClientID:        idp.GetClientId(),
		ClientSecret:    idp.GetClientSecret(),
		Scopes:          idp.GetScopes(),
		AuthCodeOptions: idp.GetRequestParams(),
	})
}

func IdentityProviderLookupFromCache(idpCache *config.IdentityProviderCache) func(*config.Options, string) (identity.Authenticator, error) {
	return func(options *config.Options, idpID string) (identity.Authenticator, error) {
		idp, err := idpCache.GetIdentityProviderByID(idpID)
		if err != nil {
			return nil, err
		}
		return NewAuthenticator(options, idp)
	}
}
