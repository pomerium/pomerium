package config

import (
	"fmt"

	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/pkg/grpc/identity"
)

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
		if p.Matches(*u, o.IsRuntimeFlagSet(RuntimeFlagMatchAnyIncomingPort)) {
			return o.GetIdentityProviderForPolicy(p)
		}
	}
	return o.GetIdentityProviderForPolicy(nil)
}

type IdentityProviderCache struct {
	idpsByRouteID     map[uint64]*identity.Provider
	policiesByRouteID map[uint64]*Policy
	idpsByID          map[string]*identity.Provider
}

func NewIdentityProviderCache(opts *Options) (*IdentityProviderCache, error) {
	rt := &IdentityProviderCache{
		idpsByRouteID:     make(map[uint64]*identity.Provider, opts.NumPolicies()),
		policiesByRouteID: make(map[uint64]*Policy, opts.NumPolicies()),
		idpsByID:          make(map[string]*identity.Provider),
	}

	for policy := range opts.GetAllPolicies() {
		id, err := policy.RouteID()
		if err != nil {
			return nil, err
		}
		idp, err := opts.GetIdentityProviderForPolicy(policy)
		if err != nil {
			return nil, err
		}
		rt.idpsByRouteID[id] = idp
		rt.policiesByRouteID[id] = policy

		if _, ok := rt.idpsByID[idp.Id]; !ok {
			rt.idpsByID[idp.Id] = idp
		}
	}
	return rt, nil
}

func (rt *IdentityProviderCache) GetIdentityProviderForPolicy(policy *Policy) (*identity.Provider, error) {
	routeID, err := policy.RouteID()
	if err != nil {
		return nil, err
	}
	idp, ok := rt.idpsByRouteID[routeID]
	if !ok {
		return nil, fmt.Errorf("no identity provider found for route %d", routeID)
	}
	return idp, nil
}

func (rt *IdentityProviderCache) GetIdentityProviderForRouteID(routeID uint64) (*identity.Provider, error) {
	idp, ok := rt.idpsByRouteID[routeID]
	if !ok {
		return nil, fmt.Errorf("no identity provider found for route %d", routeID)
	}
	return idp, nil
}

func (rt *IdentityProviderCache) GetIdentityProviderByID(idpID string) (*identity.Provider, error) {
	idp, ok := rt.idpsByID[idpID]
	if !ok {
		return nil, fmt.Errorf("no identity provider found for id %s", idpID)
	}
	return idp, nil
}

func (rt *IdentityProviderCache) GetPolicyByID(routeID uint64) (*Policy, error) {
	policy, ok := rt.policiesByRouteID[routeID]
	if !ok {
		return nil, fmt.Errorf("no policy found for route %d", routeID)
	}
	return policy, nil
}
