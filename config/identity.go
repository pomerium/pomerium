package config

import (
	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/pkg/grpc/identity"
)

// GetIdentityProviderForID returns the identity provider associated with the given IDP id.
// If none is found the default provider is returned.
func (o *Options) GetIdentityProviderForID(idpID string) (*identity.Provider, error) {
	for p := range o.GetAllPolicies() {
		idp, err := o.GetIdentityProviderForPolicy(p)
		if err != nil {
			return nil, err
		}
		if idp.GetId() == idpID {
			return idp, nil
		}
	}

	return o.GetIdentityProviderForPolicy(nil)
}

// GetIdentityProviderForPolicy gets the identity provider associated with the given policy.
// If policy is nil, or changes none of the default settings, the default provider is returned.
func (o *Options) GetIdentityProviderForPolicy(policy *Policy) (*identity.Provider, error) {
	clientSecret, err := o.GetClientSecret()
	if err != nil {
		return nil, err
	}

	authenticateURL, err := o.GetAuthenticateURL()
	if err != nil {
		return nil, err
	}

	idp := &identity.Provider{
		AuthenticateServiceUrl: authenticateURL.String(),
		ClientId:               o.ClientID,
		ClientSecret:           clientSecret,
		Type:                   o.Provider,
		Scopes:                 o.Scopes,
		Url:                    o.ProviderURL,
		RequestParams:          o.RequestParams,
	}
	if policy != nil {
		if policy.IDPClientID != "" {
			idp.ClientId = policy.IDPClientID
		}
		if policy.IDPClientSecret != "" {
			idp.ClientSecret = policy.IDPClientSecret
		}
	}
	idp.Id = idp.Hash()
	return idp, nil
}

// GetIdentityProviderForRequestURL gets the identity provider associated with the given request URL.
func (o *Options) GetIdentityProviderForRequestURL(requestURL string) (*identity.Provider, error) {
	u, err := urlutil.ParseAndValidateURL(requestURL)
	if err != nil {
		return nil, err
	}

	for p := range o.GetAllPolicies() {
		if p.Matches(u, o.IsRuntimeFlagSet(RuntimeFlagMatchAnyIncomingPort)) {
			return o.GetIdentityProviderForPolicy(p)
		}
	}
	return o.GetIdentityProviderForPolicy(nil)
}
