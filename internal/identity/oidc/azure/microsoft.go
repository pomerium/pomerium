// Package azure implements OpenID Connect for Microsoft Azure
//
// https://www.pomerium.io/docs/identity-providers/azure.html
package azure

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	go_oidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/pomerium/pomerium/internal/identity/oauth"
	pom_oidc "github.com/pomerium/pomerium/internal/identity/oidc"
)

// Name identifies the Azure identity provider
const Name = "azure"

// defaultProviderURL Users with both a personal Microsoft
// account and a work or school account from Azure Active Directory (Azure AD)
// an sign in to the application.
const defaultProviderURL = "https://login.microsoftonline.com/common/v2.0"

// nonSpecIssuerURL is the non-oidc spec issuer url which azure will reply with
// if using the defaultProviderURL.
// https://github.com/MicrosoftDocs/azure-docs/issues/38427#issuecomment-705892340
const nonSpecIssuerURL = "https://login.microsoftonline.com/{tenantid}/v2.0"

// https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-auth-code-flow#request-an-authorization-code
var defaultAuthCodeOptions = map[string]string{"prompt": "select_account"}

// Provider is an Azure implementation of the Authenticator interface.
type Provider struct {
	*pom_oidc.Provider
}

// New instantiates an OpenID Connect (OIDC) provider for Azure.
func New(ctx context.Context, o *oauth.Options) (*Provider, error) {
	var p Provider
	var err error
	if o.ProviderURL == "" {
		o.ProviderURL = defaultProviderURL
	}
	genericOidc, err := newProvider(ctx, o,
		pom_oidc.WithGetVerifier(func(provider *go_oidc.Provider) *go_oidc.IDTokenVerifier {
			return provider.Verifier(&go_oidc.Config{
				ClientID: o.ClientID,
				// If using the common endpoint, the verification provider URI will not match.
				// https://github.com/pomerium/pomerium/issues/1605
				SkipIssuerCheck: o.ProviderURL == defaultProviderURL,
			})
		}))
	if err != nil {
		return nil, fmt.Errorf("%s: failed creating oidc provider: %w", Name, err)
	}
	p.Provider = genericOidc

	p.AuthCodeOptions = defaultAuthCodeOptions
	if len(o.AuthCodeOptions) != 0 {
		p.AuthCodeOptions = o.AuthCodeOptions
	}

	return &p, nil
}

// Name returns the provider name.
func (p *Provider) Name() string {
	return Name
}

// newProvider overrides the default round tripper for well-known endpoint call that happens
// on new provider registration.
// By default, the "common" (both public and private domains) responds with
// https://login.microsoftonline.com/{tenantid}/v2.0 for issuer which is not OIDC spec.
// If {tenantid} is in the issuer string, we force the issuer to match the defaultURL.
//
// https://github.com/pomerium/pomerium/issues/1605
func newProvider(ctx context.Context, o *oauth.Options, options ...pom_oidc.Option) (*pom_oidc.Provider, error) {
	originalClient := http.DefaultClient
	if c, ok := ctx.Value(oauth2.HTTPClient).(*http.Client); ok {
		originalClient = c
	}

	client := new(http.Client)
	*client = *originalClient
	client.Transport = &wellKnownConfiguration{underlying: client.Transport}

	ctx = context.WithValue(ctx, oauth2.HTTPClient, client)
	return pom_oidc.New(ctx, o, options...)
}

type wellKnownConfiguration struct {
	underlying http.RoundTripper
}

func (transport *wellKnownConfiguration) RoundTrip(req *http.Request) (*http.Response, error) {
	underlying := transport.underlying
	if underlying == nil {
		underlying = http.DefaultTransport
	}

	res, err := underlying.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	bs, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	var wk map[string]interface{}
	if err := json.Unmarshal(bs, &wk); err == nil {
		if issuerVar, ok := wk["issuer"]; ok {
			if fmt.Sprint(issuerVar) == nonSpecIssuerURL {
				wk["issuer"] = defaultProviderURL
			}
		}
		bs, _ = json.Marshal(wk)
	}

	res.Body = ioutil.NopCloser(bytes.NewReader(bs))
	return res, nil
}
