// Package azure implements OpenID Connect for Microsoft Azure
//
// https://www.pomerium.com/docs/identity-providers/azure
package azure

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	go_oidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/uuid"
	"golang.org/x/oauth2"

	"github.com/pomerium/pomerium/internal/jwtutil"
	"github.com/pomerium/pomerium/pkg/identity/oauth"
	pom_oidc "github.com/pomerium/pomerium/pkg/identity/oidc"
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
	accessTokenAllowedAudiences *[]string

	mu                     sync.RWMutex
	accessTokenVerifierCtx context.Context
	accessTokenVerifier    *go_oidc.IDTokenVerifier
}

// New instantiates an OpenID Connect (OIDC) provider for Azure.
func New(ctx context.Context, o *oauth.Options) (*Provider, error) {
	var p Provider
	p.accessTokenAllowedAudiences = o.AccessTokenAllowedAudiences
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
	if o.AuthCodeOptions != nil {
		p.AuthCodeOptions = o.AuthCodeOptions
	}

	p.accessTokenVerifierCtx = ctx

	return &p, nil
}

// Name returns the provider name.
func (p *Provider) Name() string {
	return Name
}

// VerifyAccessToken verifies a raw access token.
func (p *Provider) VerifyAccessToken(ctx context.Context, rawAccessToken string) (claims map[string]any, err error) {
	pp, err := p.GetProvider()
	if err != nil {
		return nil, fmt.Errorf("error getting oidc provider: %w", err)
	}

	verifier := p.getAccessTokenVerifier(pp)
	token, err := verifier.Verify(ctx, rawAccessToken)
	if err != nil {
		return nil, fmt.Errorf("error verifying access token: %w", err)
	}

	claims = jwtutil.Claims(map[string]any{})
	err = token.Claims(&claims)
	if err != nil {
		return nil, fmt.Errorf("error unmarshaling access token claims: %w", err)
	}

	// verify audience
	if p.accessTokenAllowedAudiences != nil {
		if audience, ok := claims["aud"].(string); !ok || !slices.Contains(*p.accessTokenAllowedAudiences, audience) {
			return nil, fmt.Errorf("error verifying access token audience claim, invalid audience")
		}
	}

	err = verifyIssuer(pp, claims)
	if err != nil {
		return nil, fmt.Errorf("error verifying access token issuer claim: %w", err)
	}

	if scope, ok := claims["scp"].(string); ok && slices.Contains(strings.Fields(scope), "openid") {
		userInfo, err := pp.UserInfo(ctx, oauth2.StaticTokenSource(&oauth2.Token{
			TokenType:   "Bearer",
			AccessToken: rawAccessToken,
		}))
		if err != nil {
			return nil, fmt.Errorf("error calling user info endpoint: %w", err)
		}

		err = userInfo.Claims(claims)
		if err != nil {
			return nil, fmt.Errorf("error unmarshaling user info claims: %w", err)
		}
	}

	return claims, nil
}

func (p *Provider) getAccessTokenVerifier(pp *go_oidc.Provider) *go_oidc.IDTokenVerifier {
	p.mu.RLock()
	accessTokenVerifier := p.accessTokenVerifier
	p.mu.RUnlock()

	if accessTokenVerifier != nil {
		return accessTokenVerifier
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	accessTokenVerifier = p.accessTokenVerifier
	if accessTokenVerifier != nil {
		return accessTokenVerifier
	}

	// azure access tokens are JWTs signed with the same keys as identity tokens

	ctx := p.accessTokenVerifierCtx

	// add a timeout for all http requests
	httpClient := &http.Client{}
	if c, ok := ctx.Value(oauth2.HTTPClient).(*http.Client); ok {
		*httpClient = *c
	}
	httpClient.Timeout = 10 * time.Second
	ctx = context.WithValue(ctx, oauth2.HTTPClient, httpClient)

	p.accessTokenVerifier = pp.VerifierContext(ctx, &go_oidc.Config{
		SkipClientIDCheck: true,
		SkipIssuerCheck:   true, // checked later
	})
	return p.accessTokenVerifier
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
	return pom_oidc.NewWithOptions(ctx, o, options...)
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

	bs, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	var wk map[string]any
	if err := json.Unmarshal(bs, &wk); err == nil {
		if issuerVar, ok := wk["issuer"]; ok {
			if fmt.Sprint(issuerVar) == nonSpecIssuerURL {
				wk["issuer"] = defaultProviderURL
			}
		}
		bs, _ = json.Marshal(wk)
	}

	res.Body = io.NopCloser(bytes.NewReader(bs))
	return res, nil
}

const (
	v1IssuerPrefix = "https://sts.windows.net/"
	v1IssuerSuffix = "/"
	v2IssuerPrefix = "https://login.microsoftonline.com/"
	v2IssuerSuffix = "/v2.0"
)

func verifyIssuer(pp *go_oidc.Provider, claims map[string]any) error {
	tenantID, ok := getTenantIDFromURL(pp.Endpoint().TokenURL)
	if !ok {
		return fmt.Errorf("failed to find tenant id")
	}

	iss, ok := claims["iss"].(string)
	if !ok {
		return fmt.Errorf("missing issuer claim")
	}

	if !(iss == v1IssuerPrefix+tenantID+v1IssuerSuffix || iss == v2IssuerPrefix+tenantID+v2IssuerSuffix) {
		return fmt.Errorf("invalid issuer: %s", iss)
	}

	return nil
}

func getTenantIDFromURL(rawTokenURL string) (string, bool) {
	// URLs look like:
	// - https://login.microsoftonline.com/f42bce3b-671c-4162-b24c-00ecc7641897/v2.0
	// Or:
	// - https://sts.windows.net/f42bce3b-671c-4162-b24c-00ecc7641897/
	for _, prefix := range []string{v1IssuerPrefix, v2IssuerPrefix} {
		path, ok := strings.CutPrefix(rawTokenURL, prefix)
		if !ok {
			continue
		}

		idx := strings.Index(path, "/")
		if idx <= 0 {
			continue
		}

		rawTenantID := path[:idx]
		if _, err := uuid.Parse(rawTenantID); err != nil {
			continue
		}

		return rawTenantID, true
	}

	return "", false
}
