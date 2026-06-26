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

// JWTAllowedIssuer declares a trusted JWT issuer. Pomerium verifies JWT bearer
// tokens against any of these issuers on routes whose BearerTokenFormat is
// BEARER_TOKEN_FORMAT_JWT. Audience binding is enforced separately, via the
// route/global JWTAllowedAudiences; authorization on the verified claims is
// left to PPL (claim/...).
type JWTAllowedIssuer struct {
	// Issuer is the `iss` claim tokens must carry. Required. Used both to
	// select the matching issuer for an incoming token and (with OIDC
	// discovery) to fetch the signing keys.
	Issuer string `mapstructure:"issuer" yaml:"issuer"`
	// JWKSURL is an optional explicit JWKS URL. When set, OIDC discovery is
	// skipped — keys are fetched directly from this URL. Useful when the
	// issuer URL is not externally routable (e.g. Kubernetes'
	// `https://kubernetes.default.svc.cluster.local`).
	JWKSURL string `mapstructure:"jwks_url" yaml:"jwks_url,omitempty"`
	// SupportedAlgs is the JWT signing algorithms allowlist. When empty,
	// defaults to {RS256, ES256, EdDSA}.
	SupportedAlgs []string `mapstructure:"supported_algs" yaml:"supported_algs,omitempty"`
	// Name is an optional human-readable identifier, used only for audit
	// logging.
	Name string `mapstructure:"name" yaml:"name,omitempty"`
}

// DefaultJWTSupportedAlgs is used when a JWTAllowedIssuer does not specify
// SupportedAlgs. Avoids the go-oidc default of "RS256 only" so that ES256
// (SPIFFE, some EKS configurations) and EdDSA-signed tokens are accepted out
// of the box.
var DefaultJWTSupportedAlgs = []string{"RS256", "ES256", "EdDSA"}

// Validate checks that the JWTAllowedIssuer is well-formed.
func (p *JWTAllowedIssuer) Validate() error {
	if p.Issuer == "" {
		return fmt.Errorf("jwt_allowed_issuers: issuer is required")
	}
	if _, err := url.Parse(p.Issuer); err != nil {
		return fmt.Errorf("jwt_allowed_issuers[%s]: invalid issuer URL: %w", p.Issuer, err)
	}
	if p.JWKSURL != "" {
		u, err := url.Parse(p.JWKSURL)
		if err != nil {
			return fmt.Errorf("jwt_allowed_issuers[%s]: invalid jwks_url: %w", p.Issuer, err)
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return fmt.Errorf("jwt_allowed_issuers[%s]: jwks_url must be http(s)", p.Issuer)
		}
	}
	return nil
}

// EffectiveSupportedAlgs returns p.SupportedAlgs or the default allowlist.
func (p *JWTAllowedIssuer) EffectiveSupportedAlgs() []string {
	if len(p.SupportedAlgs) > 0 {
		return slices.Clone(p.SupportedAlgs)
	}
	return slices.Clone(DefaultJWTSupportedAlgs)
}

// jwtAllowedIssuersToProto converts the Options slice to its proto form.
func jwtAllowedIssuersToProto(src []JWTAllowedIssuer) []*configpb.JwtAllowedIssuer {
	if len(src) == 0 {
		return nil
	}
	out := make([]*configpb.JwtAllowedIssuer, 0, len(src))
	for _, p := range src {
		pb := &configpb.JwtAllowedIssuer{
			Issuer:        p.Issuer,
			JwksUrl:       p.JWKSURL,
			SupportedAlgs: slices.Clone(p.SupportedAlgs),
		}
		if p.Name != "" {
			pb.Name = &p.Name
		}
		out = append(out, pb)
	}
	return out
}

// setJWTAllowedIssuers copies the proto slice into the Options slot.
//
// Follows the same pattern as setSlice / setMap elsewhere in this package:
// if the incoming slice is empty we DO NOT clear the destination — empty in
// proto can mean "not set in this fragment" (multiple Settings fragments are
// merged sequentially via ApplySettings), and clearing would clobber an
// earlier fragment.
func setJWTAllowedIssuers(dst *[]JWTAllowedIssuer, src []*configpb.JwtAllowedIssuer) {
	if len(src) == 0 {
		return
	}
	out := make([]JWTAllowedIssuer, 0, len(src))
	for _, p := range src {
		out = append(out, JWTAllowedIssuer{
			Issuer:        p.GetIssuer(),
			JWKSURL:       p.GetJwksUrl(),
			SupportedAlgs: slices.Clone(p.GetSupportedAlgs()),
			Name:          p.GetName(),
		})
	}
	*dst = out
}

// validateJWTBearerTokens checks the BEARER_TOKEN_FORMAT_JWT configuration:
// trusted issuers are well-formed and unique, and every route that resolves to
// the JWT format has at least one trusted issuer and a non-empty (fail-closed)
// audience allowlist.
func (o *Options) validateJWTBearerTokens() error {
	seen := make(map[string]struct{}, len(o.JWTAllowedIssuers))
	for i := range o.JWTAllowedIssuers {
		iss := &o.JWTAllowedIssuers[i]
		if err := iss.Validate(); err != nil {
			return fmt.Errorf("config: %w", err)
		}
		if _, dup := seen[iss.Issuer]; dup {
			return fmt.Errorf("config: jwt_allowed_issuers: duplicate issuer %q", iss.Issuer)
		}
		seen[iss.Issuer] = struct{}{}
	}

	globalFormat := configpb.BearerTokenFormat_BEARER_TOKEN_FORMAT_UNKNOWN
	if o.BearerTokenFormat.IsSet {
		globalFormat = o.BearerTokenFormat.Value
	}
	isJWT := func(p *Policy) bool {
		if p.BearerTokenFormat.IsSet {
			return p.BearerTokenFormat.Value == configpb.BearerTokenFormat_BEARER_TOKEN_FORMAT_JWT
		}
		return globalFormat == configpb.BearerTokenFormat_BEARER_TOKEN_FORMAT_JWT
	}

	for p := range o.GetAllPolicies() {
		if !isJWT(p) {
			continue
		}
		if len(o.JWTAllowedIssuers) == 0 {
			return fmt.Errorf("config: bearer_token_format=jwt requires at least one jwt_allowed_issuers entry (route %q)", p.String())
		}
		audiences := p.JWTAllowedAudiences
		if audiences == nil {
			audiences = o.JWTAllowedAudiences
		}
		if len(ptrSlice(audiences)) == 0 {
			return fmt.Errorf("config: bearer_token_format=jwt requires a non-empty jwt_allowed_audiences (route %q)", p.String())
		}
	}
	return nil
}

func ptrSlice(s *[]string) []string {
	if s == nil {
		return nil
	}
	return *s
}

// GetJWTAllowedAudiencesForPolicy resolves the effective JWT audience
// allowlist for the policy: per-route override, else the global default, else
// nil. An empty/nil result is fail-closed downstream (the verifier rejects).
func (cfg *Config) GetJWTAllowedAudiencesForPolicy(policy *Policy) []string {
	if policy != nil && policy.JWTAllowedAudiences != nil {
		return *policy.JWTAllowedAudiences
	}
	if cfg != nil && cfg.Options != nil && cfg.Options.JWTAllowedAudiences != nil {
		return *cfg.Options.JWTAllowedAudiences
	}
	return nil
}

// ErrNoMatchingJWTIssuer is returned by JWTIssuerResolver.Verify when the
// token's `iss` claim does not match any configured trusted issuer.
var ErrNoMatchingJWTIssuer = errors.New("config/jwt_idp: no trusted issuer matches the token's iss claim")

// JWTVerifyResult is the successful outcome of JWTIssuerResolver.Verify.
type JWTVerifyResult struct {
	// Issuer is the `iss` of the trusted issuer that verified the token.
	// Useful for audit logs and as a session-cache namespace.
	Issuer string
	// Claims is the verified JWT payload.
	Claims map[string]any
}

// JWTIssuerResolver owns one *extjwt.Provider per trusted issuer and verifies
// incoming bearer tokens against whichever issuer matches the token's `iss`.
//
// Construct once per Options snapshot; the provider instances are immutable
// after creation.
type JWTIssuerResolver struct {
	providers map[string]*extjwt.Provider // key: issuer
}

// JWTIssuerResolver returns a cached resolver built from cfg.Options. Built
// once per Config instance. Returns nil if no trusted issuers are configured.
func (cfg *Config) JWTIssuerResolver() (*JWTIssuerResolver, error) {
	if cfg == nil || cfg.Options == nil || len(cfg.Options.JWTAllowedIssuers) == 0 {
		return nil, nil
	}
	cfg.jwtResolverOnce.Do(func() {
		cfg.jwtResolver, cfg.jwtResolverErr = NewJWTIssuerResolver(cfg.Options.JWTAllowedIssuers)
	})
	return cfg.jwtResolver, cfg.jwtResolverErr
}

// NewJWTIssuerResolver builds a resolver from the given issuers. Returns an
// error if any issuer is invalid or two share the same `issuer`.
func NewJWTIssuerResolver(issuers []JWTAllowedIssuer) (*JWTIssuerResolver, error) {
	r := &JWTIssuerResolver{
		providers: make(map[string]*extjwt.Provider, len(issuers)),
	}
	for _, iss := range issuers {
		if err := iss.Validate(); err != nil {
			return nil, err
		}
		if _, dup := r.providers[iss.Issuer]; dup {
			return nil, fmt.Errorf("jwt_allowed_issuers: duplicate issuer %q", iss.Issuer)
		}
		p, err := extjwt.New(extjwt.Config{
			Issuer:        iss.Issuer,
			JWKSURL:       iss.JWKSURL,
			SupportedAlgs: iss.EffectiveSupportedAlgs(),
		})
		if err != nil {
			return nil, fmt.Errorf("jwt_allowed_issuers[%s]: %w", iss.Issuer, err)
		}
		r.providers[iss.Issuer] = p
	}
	return r, nil
}

// Verify verifies the raw JWT against the trusted issuer whose `issuer`
// matches the token's `iss` claim.
//
// Dispatch:
//  1. Parse the token's `iss` claim (no signature check yet).
//  2. Look up the trusted issuer with that `iss`.
//  3. Verify signature/exp/nbf via that issuer's provider, with `aud` checked
//     against allowedAudiences (fail-closed: an empty allowlist rejects).
//
// Returns ErrNoMatchingJWTIssuer if no trusted issuer matches.
func (r *JWTIssuerResolver) Verify(ctx context.Context, rawJWT string, allowedAudiences []string) (*JWTVerifyResult, error) {
	iss, err := unverifiedIssuer(rawJWT)
	if err != nil {
		return nil, fmt.Errorf("config/jwt_idp: parse iss: %w", err)
	}
	p, ok := r.providers[iss]
	if !ok {
		return nil, ErrNoMatchingJWTIssuer
	}
	claims, err := p.Verify(ctx, rawJWT, allowedAudiences)
	if err != nil {
		return nil, err
	}
	return &JWTVerifyResult{
		Issuer: iss,
		Claims: claims,
	}, nil
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
