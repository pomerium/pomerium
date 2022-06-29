package config

import (
	"github.com/pomerium/pomerium/pkg/grpc/identity"
)

// GetIdentityProviderForID returns the identity provider associated with the given IDP id.
// If none is found the default provider is returned.
func (o *Options) GetIdentityProviderForID(idpID string) (*identity.Provider, error) {
	for _, policy := range o.GetAllPolicies() {
		idp, err := o.GetIdentityProviderForPolicy(&policy) //nolint
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

	idp := &identity.Provider{
		ClientId:       o.ClientID,
		ClientSecret:   clientSecret,
		Type:           o.Provider,
		Scopes:         o.Scopes,
		ServiceAccount: o.ServiceAccount,
		Url:            o.ProviderURL,
		RequestParams:  o.RequestParams,
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
