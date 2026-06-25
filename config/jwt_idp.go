package config

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"

	"github.com/pomerium/pomerium/pkg/identity/oidc/extjwt"

	configpb "github.com/pomerium/pomerium/pkg/grpc/config"
)

// JWTIdentityProvider declares a verify-only JWT issuer. Pomerium accepts
// JWTs from this issuer on routes that opt in via Policy.AcceptJWTIdps.
//
// See docs/jwt-idps-change-plan.md.
type JWTIdentityProvider struct {
	// Name is a stable identifier referenced by Policy.AcceptJWTIdps[].Name.
	Name string `mapstructure:"name" yaml:"name"`
	// Issuer is the `iss` claim tokens must carry. Required.
	Issuer string `mapstructure:"issuer" yaml:"issuer"`
	// JWKSURL is an optional explicit JWKS URL. When set, OIDC discovery is
	// skipped — keys are fetched directly from this URL. Useful when the
	// issuer URL is not externally routable (e.g. Kubernetes'
	// `https://kubernetes.default.svc.cluster.local`).
	JWKSURL string `mapstructure:"jwks_url" yaml:"jwks_url,omitempty"`
	// SupportedAlgs is the JWT signing algorithms allowlist. When empty,
	// defaults to {RS256, ES256, EdDSA}.
	SupportedAlgs []string `mapstructure:"supported_algs" yaml:"supported_algs,omitempty"`
}

// DefaultJWTSupportedAlgs is used when a JWTIdentityProvider does not specify
// SupportedAlgs. Avoids the go-oidc default of "RS256 only" so that ES256
// (SPIFFE, some EKS configurations) and EdDSA-signed tokens are accepted out
// of the box.
var DefaultJWTSupportedAlgs = []string{"RS256", "ES256", "EdDSA"}

// Validate checks that the JWTIdentityProvider is well-formed.
func (p *JWTIdentityProvider) Validate() error {
	if p.Name == "" {
		return fmt.Errorf("jwt_identity_providers: name is required")
	}
	if p.Issuer == "" {
		return fmt.Errorf("jwt_identity_providers[%s]: issuer is required", p.Name)
	}
	if _, err := url.Parse(p.Issuer); err != nil {
		return fmt.Errorf("jwt_identity_providers[%s]: invalid issuer URL: %w", p.Name, err)
	}
	if p.JWKSURL != "" {
		u, err := url.Parse(p.JWKSURL)
		if err != nil {
			return fmt.Errorf("jwt_identity_providers[%s]: invalid jwks_url: %w", p.Name, err)
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return fmt.Errorf("jwt_identity_providers[%s]: jwks_url must be http(s)", p.Name)
		}
	}
	return nil
}

// EffectiveSupportedAlgs returns p.SupportedAlgs or the default allowlist.
func (p *JWTIdentityProvider) EffectiveSupportedAlgs() []string {
	if len(p.SupportedAlgs) > 0 {
		return slices.Clone(p.SupportedAlgs)
	}
	return slices.Clone(DefaultJWTSupportedAlgs)
}

// JWTIdpAcceptance is a per-route reference to a globally-declared
// JWTIdentityProvider, scoped to a specific audience set.
type JWTIdpAcceptance struct {
	// Name matches a JWTIdentityProvider declared in Options.JWTIdentityProviders.
	Name string `mapstructure:"name" yaml:"name"`
	// Audiences is the set of `aud` values accepted on this route. At least
	// one of these must appear in the JWT's `aud` claim. Required and must
	// be non-empty.
	Audiences []string `mapstructure:"audiences" yaml:"audiences"`
}

// Validate checks that the JWTIdpAcceptance is well-formed.
func (a *JWTIdpAcceptance) Validate() error {
	if a.Name == "" {
		return fmt.Errorf("accept_jwt_idps: name is required")
	}
	if len(a.Audiences) == 0 {
		return fmt.Errorf("accept_jwt_idps[%s]: audiences must be non-empty", a.Name)
	}
	return nil
}

// jwtIdentityProvidersToProto converts the Options slice to its proto form.
func jwtIdentityProvidersToProto(src []JWTIdentityProvider) []*configpb.JwtIdentityProvider {
	if len(src) == 0 {
		return nil
	}
	out := make([]*configpb.JwtIdentityProvider, 0, len(src))
	for _, p := range src {
		out = append(out, &configpb.JwtIdentityProvider{
			Name:          p.Name,
			Issuer:        p.Issuer,
			JwksUrl:       p.JWKSURL,
			SupportedAlgs: slices.Clone(p.SupportedAlgs),
		})
	}
	return out
}

// setJWTIdentityProviders copies the proto slice into the Options slot.
//
// Follows the same pattern as setSlice / setMap elsewhere in this package:
// if the incoming slice is empty we DO NOT clear the destination — empty in
// proto can mean "not set in this fragment" (multiple Settings fragments are
// merged sequentially via ApplySettings), and clearing would clobber an
// earlier fragment.
func setJWTIdentityProviders(dst *[]JWTIdentityProvider, src []*configpb.JwtIdentityProvider) {
	if len(src) == 0 {
		return
	}
	out := make([]JWTIdentityProvider, 0, len(src))
	for _, p := range src {
		out = append(out, JWTIdentityProvider{
			Name:          p.GetName(),
			Issuer:        p.GetIssuer(),
			JWKSURL:       p.GetJwksUrl(),
			SupportedAlgs: slices.Clone(p.GetSupportedAlgs()),
		})
	}
	*dst = out
}

// acceptJWTIdpsToProto converts the Policy slice to its proto form.
func acceptJWTIdpsToProto(src []JWTIdpAcceptance) []*configpb.JwtIdpAcceptance {
	if len(src) == 0 {
		return nil
	}
	out := make([]*configpb.JwtIdpAcceptance, 0, len(src))
	for _, a := range src {
		out = append(out, &configpb.JwtIdpAcceptance{
			Name:      a.Name,
			Audiences: slices.Clone(a.Audiences),
		})
	}
	return out
}

// acceptJWTIdpsFromProto reads the proto slice into the Policy slot.
func acceptJWTIdpsFromProto(src []*configpb.JwtIdpAcceptance) []JWTIdpAcceptance {
	if len(src) == 0 {
		return nil
	}
	out := make([]JWTIdpAcceptance, 0, len(src))
	for _, a := range src {
		out = append(out, JWTIdpAcceptance{
			Name:      a.GetName(),
			Audiences: slices.Clone(a.GetAudiences()),
		})
	}
	return out
}

// FindJWTIdentityProvider returns the globally-declared provider with the
// given name, or nil.
func (o *Options) FindJWTIdentityProvider(name string) *JWTIdentityProvider {
	for i := range o.JWTIdentityProviders {
		if o.JWTIdentityProviders[i].Name == name {
			return &o.JWTIdentityProviders[i]
		}
	}
	return nil
}

// ErrNoMatchingJWTIdp is returned by JWTIdpResolver.VerifyForPolicy when no
// configured provider satisfies the JWT's issuer and the policy's acceptance
// list.
var ErrNoMatchingJWTIdp = errors.New("config/jwt_idp: no matching JWT identity provider for token")

// JWTVerifyResult is the successful outcome of VerifyForPolicy.
type JWTVerifyResult struct {
	// ProviderName is the name of the JwtIdentityProvider that verified the
	// token. Useful for audit logs.
	ProviderName string
	// Claims is the verified JWT payload.
	Claims map[string]any
}

// JWTIdpResolver owns the per-named-IdP *extjwt.Provider instances and
// performs per-route dispatch of incoming bearer tokens.
//
// Construct once per Options snapshot; the resolver instances are immutable
// after creation.
type JWTIdpResolver struct {
	providers map[string]*extjwt.Provider // key: JwtIdentityProvider.Name
	configs   map[string]JWTIdentityProvider
}

// JWTIdpResolver returns a cached resolver built from cfg.Options. Re-built
// on the first access of each Config instance. Returns nil if no JWT
// identity providers are configured.
func (cfg *Config) JWTIdpResolver() (*JWTIdpResolver, error) {
	if cfg == nil || cfg.Options == nil || len(cfg.Options.JWTIdentityProviders) == 0 {
		return nil, nil
	}
	cfg.jwtResolverOnce.Do(func() {
		cfg.jwtResolver, cfg.jwtResolverErr = NewJWTIdpResolver(cfg.Options.JWTIdentityProviders)
	})
	return cfg.jwtResolver, cfg.jwtResolverErr
}

// NewJWTIdpResolver builds a resolver from the given configurations. Returns
// an error if any configuration is invalid.
func NewJWTIdpResolver(idps []JWTIdentityProvider) (*JWTIdpResolver, error) {
	r := &JWTIdpResolver{
		providers: make(map[string]*extjwt.Provider, len(idps)),
		configs:   make(map[string]JWTIdentityProvider, len(idps)),
	}
	for _, idp := range idps {
		if err := idp.Validate(); err != nil {
			return nil, err
		}
		if _, dup := r.providers[idp.Name]; dup {
			return nil, fmt.Errorf("jwt_identity_providers: duplicate name %q", idp.Name)
		}
		p, err := extjwt.New(extjwt.Config{
			Issuer:        idp.Issuer,
			JWKSURL:       idp.JWKSURL,
			SupportedAlgs: idp.EffectiveSupportedAlgs(),
		})
		if err != nil {
			return nil, fmt.Errorf("jwt_identity_providers[%s]: %w", idp.Name, err)
		}
		r.providers[idp.Name] = p
		r.configs[idp.Name] = idp
	}
	return r, nil
}

// VerifyForPolicy verifies the raw JWT against whichever JwtIdentityProvider
// the policy accepts AND whose issuer matches the token's `iss` claim.
//
// Dispatch:
//  1. Parse the token's `iss` claim (no signature check yet).
//  2. Iterate the policy's AcceptJWTIdps; pick the first whose named
//     provider matches the JWT's `iss`.
//  3. Verify signature/exp/nbf via that provider, with `aud` checked against
//     the matching acceptance entry's audiences.
//
// Returns ErrNoMatchingJWTIdp if no acceptance entry matches.
func (r *JWTIdpResolver) VerifyForPolicy(ctx context.Context, accept []JWTIdpAcceptance, rawJWT string) (*JWTVerifyResult, error) {
	if len(accept) == 0 {
		return nil, ErrNoMatchingJWTIdp
	}
	iss, err := unverifiedIssuer(rawJWT)
	if err != nil {
		return nil, fmt.Errorf("config/jwt_idp: parse iss: %w", err)
	}
	for _, entry := range accept {
		p, ok := r.providers[entry.Name]
		if !ok {
			continue
		}
		cfg, ok := r.configs[entry.Name]
		if !ok || cfg.Issuer != iss {
			continue
		}
		claims, err := p.Verify(ctx, rawJWT, entry.Audiences)
		if err != nil {
			return nil, err
		}
		return &JWTVerifyResult{
			ProviderName: entry.Name,
			Claims:       claims,
		}, nil
	}
	return nil, ErrNoMatchingJWTIdp
}

// unverifiedIssuer extracts the `iss` claim from the JWT payload WITHOUT
// verifying the signature. Used only to dispatch to the correct verifier;
// the matched verifier then performs full verification including signature
// and `iss` re-check.
func unverifiedIssuer(rawJWT string) (string, error) {
	parts := strings.SplitN(rawJWT, ".", 3)
	if len(parts) != 3 {
		return "", fmt.Errorf("malformed JWT (expected 3 parts)")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("decode payload: %w", err)
	}
	var c struct {
		Iss string `json:"iss"`
	}
	if err := json.Unmarshal(payload, &c); err != nil {
		return "", fmt.Errorf("unmarshal payload: %w", err)
	}
	if c.Iss == "" {
		return "", fmt.Errorf("missing iss claim")
	}
	return c.Iss, nil
}
