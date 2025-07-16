package config

import (
	"context"
	"slices"

	oteltrace "go.opentelemetry.io/otel/trace"

	"github.com/pomerium/pomerium/internal/urlutil"
	identitypb "github.com/pomerium/pomerium/pkg/grpc/identity"
	"github.com/pomerium/pomerium/pkg/identity"
	"github.com/pomerium/pomerium/pkg/identity/oauth"
)

// GetIdentityProviderForID returns the identity provider associated with the given IDP id.
// If none is found the default provider is returned.
func (o *Options) GetIdentityProviderForID(idpID string) (*identitypb.Provider, error) {
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
func (o *Options) GetIdentityProviderForPolicy(policy *Policy) (*identitypb.Provider, error) {
	clientSecret, err := o.GetClientSecret()
	if err != nil {
		return nil, err
	}

	authenticateURL, err := o.GetAuthenticateURL()
	if err != nil {
		return nil, err
	}

	idp := &identitypb.Provider{
		AuthenticateServiceUrl: authenticateURL.String(),
		ClientId:               o.ClientID,
		ClientSecret:           clientSecret,
		Type:                   o.Provider,
		Scopes:                 o.Scopes,
		Url:                    o.ProviderURL,
		RequestParams:          o.RequestParams,
	}
	if v := o.IDPAccessTokenAllowedAudiences; v != nil {
		idp.AccessTokenAllowedAudiences = &identitypb.Provider_StringList{
			Values: slices.Clone(*v),
		}
	}
	if policy != nil {
		if policy.IDPClientID != "" {
			idp.ClientId = policy.IDPClientID
		}
		if policy.IDPClientSecret != "" {
			idp.ClientSecret = policy.IDPClientSecret
		}
		if v := policy.IDPAccessTokenAllowedAudiences; v != nil {
			idp.AccessTokenAllowedAudiences = &identitypb.Provider_StringList{
				Values: slices.Clone(*v),
			}
		}
	}
	idp.Id = idp.Hash()
	return idp, nil
}

// GetIdentityProviderForRequestURL gets the identity provider associated with the given request URL.
func (o *Options) GetIdentityProviderForRequestURL(requestURL string) (*identitypb.Provider, error) {
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

// GetAuthenticator gets the authenticator for the given IDP id.
func (o *Options) GetAuthenticator(ctx context.Context, tracerProvider oteltrace.TracerProvider, idpID string) (identity.Authenticator, error) {
	authenticateURL, err := o.GetAuthenticateURL()
	if err != nil {
		return nil, err
	}

	redirectURL, err := urlutil.DeepCopy(authenticateURL)
	if err != nil {
		return nil, err
	}
	redirectURL.Path = o.AuthenticateCallbackPath

	idp, err := o.GetIdentityProviderForID(idpID)
	if err != nil {
		return nil, err
	}

	oauthOptions := oauth.Options{
		RedirectURL:     redirectURL,
		ProviderName:    idp.GetType(),
		ProviderURL:     idp.GetUrl(),
		ClientID:        idp.GetClientId(),
		ClientSecret:    idp.GetClientSecret(),
		Scopes:          idp.GetScopes(),
		AuthCodeOptions: idp.GetRequestParams(),
	}
	if v := idp.GetAccessTokenAllowedAudiences(); v != nil {
		oauthOptions.AccessTokenAllowedAudiences = &v.Values
	}
	return identity.NewAuthenticator(ctx, tracerProvider, oauthOptions)
}
