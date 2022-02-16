package config

import (
	"github.com/pomerium/pomerium/pkg/grpc/identity"
)

// GetIdentityProviderForID returns the identity provider associated with the given IDP id.
// If none is found the default provider is returned.
func (o *Options) GetIdentityProviderForID(idpID string) *identity.Provider {
	for _, policy := range o.GetAllPolicies() {
		idp := o.GetIdentityProviderForPolicy(&policy) //nolint
		if idp.GetId() == idpID {
			return idp
		}
	}

	return o.GetIdentityProviderForPolicy(nil)
}

// GetIdentityProviderForPolicy gets the identity provider associated with the given policy.
// If policy is nil, or changes none of the default settings, the default provider is returned.
func (o *Options) GetIdentityProviderForPolicy(policy *Policy) *identity.Provider {
	idp := &identity.Provider{
		ClientId:       o.ClientID,
		ClientSecret:   o.ClientSecret,
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
	return idp
}
