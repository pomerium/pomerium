// Package extjwt verifies externally-issued JWT bearer tokens (Kubernetes
// ServiceAccount tokens, GitHub Actions OIDC, SPIFFE JWT-SVIDs, etc.). It is
// intentionally NOT an identity.Authenticator — there is no OAuth2 flow, no
// SignIn, no Refresh, no UpdateUserInfo. Instances are owned by a per-route
// JWT-IdP resolver (see config) rather than registered as a global IdP.
//
// Verification steps performed by Verify:
//
//  1. JWKS fetch (OIDC discovery if JWKSURL unset; direct fetch otherwise).
//     Keys are cached and auto-refreshed via go-oidc's RemoteKeySet.
//  2. Signature verification against the JWKS, restricted to the configured
//     SupportedAlgs allowlist (defaults to RS256+ES256+EdDSA).
//  3. `iss` matches the configured Issuer.
//  4. `exp` and `nbf` checks (with go-oidc's default leeway).
//  5. `aud` claim intersects the per-call allowedAudiences set (mandatory).
//
// No claim enrichment of any kind is performed — verified claims are
// returned as-is so PPL can reference them directly via `claim/<path>`.
package extjwt

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sync"

	go_oidc "github.com/coreos/go-oidc/v3/oidc"

	"github.com/pomerium/pomerium/internal/jwtutil"
)

var (
	// ErrMissingIssuer is returned when Config.Issuer is empty.
	ErrMissingIssuer = errors.New("identity/extjwt: issuer is required")
	// ErrEmptyAudiences is returned when a Verify call passes no audiences.
	// Audience binding is mandatory; an empty set is a configuration error,
	// not "accept any."
	ErrEmptyAudiences = errors.New("identity/extjwt: at least one allowed audience is required")
	// ErrAudienceMismatch indicates the token's `aud` did not intersect the
	// configured audiences.
	ErrAudienceMismatch = errors.New("identity/extjwt: token audience does not match any allowed audience")
)

// Config configures a single verify-only JWT provider.
type Config struct {
	// Issuer is the expected JWT `iss` claim. Required.
	Issuer string
	// JWKSURL, when non-empty, skips OIDC discovery and fetches keys
	// directly from this URL. The verifier still enforces `iss == Issuer`.
	JWKSURL string
	// SupportedAlgs is the signing-algorithm allowlist. Required to be
	// non-empty; callers can fall back to a sensible default (e.g.
	// {"RS256","ES256","EdDSA"}). go-oidc would otherwise default to
	// RS256-only, silently rejecting ES256 / EdDSA tokens.
	SupportedAlgs []string
	// HTTPClient, when non-nil, is the HTTP client used to fetch the OIDC
	// discovery document and JWKS. It is injected via oidc.ClientContext, so
	// both the discovery and explicit-JWKS-URL paths honor it. Use it to
	// supply a CA-aware client for issuers behind a private CA (e.g.
	// Kubernetes' cluster CA). When nil, go-oidc's default client is used.
	HTTPClient *http.Client
}

// Provider verifies JWTs against a single trusted issuer.
type Provider struct {
	cfg Config

	mu       sync.Mutex
	verifier *go_oidc.IDTokenVerifier
}

// New creates a Provider. Lazy: JWKS fetch happens on first Verify.
func New(cfg Config) (*Provider, error) {
	if cfg.Issuer == "" {
		return nil, ErrMissingIssuer
	}
	if len(cfg.SupportedAlgs) == 0 {
		return nil, fmt.Errorf("identity/extjwt: supported_algs must be non-empty")
	}
	return &Provider{cfg: cfg}, nil
}

// Issuer returns the configured issuer URL.
func (p *Provider) Issuer() string { return p.cfg.Issuer }

// Verify verifies the raw JWT against the configured issuer and the given
// audience allowlist. Returns the verified claims map on success.
//
// allowedAudiences MUST be non-empty (an empty allowlist would silently
// accept any audience, which is forbidden — fail closed instead).
func (p *Provider) Verify(ctx context.Context, rawJWT string, allowedAudiences []string) (map[string]any, error) {
	if len(allowedAudiences) == 0 {
		return nil, ErrEmptyAudiences
	}
	v, err := p.getVerifier(ctx)
	if err != nil {
		return nil, err
	}
	tok, err := v.Verify(ctx, rawJWT)
	if err != nil {
		return nil, fmt.Errorf("identity/extjwt: token verification failed: %w", err)
	}
	if !audienceMatches(tok.Audience, allowedAudiences) {
		return nil, ErrAudienceMismatch
	}
	claims := jwtutil.Claims(map[string]any{})
	if err := tok.Claims(&claims); err != nil {
		return nil, fmt.Errorf("identity/extjwt: unmarshal claims: %w", err)
	}
	return claims, nil
}

// getVerifier lazily constructs the verifier. Two paths:
//
//   - JWKSURL set: direct JWKS fetch via NewRemoteKeySet. The configured
//     issuer is enforced as the JWT's expected `iss` even though there's
//     no OIDC discovery doc to cross-check it against.
//   - JWKSURL empty: standard OIDC discovery; go-oidc cross-checks the
//     discovery doc's `issuer` against p.cfg.Issuer.
//
// The mutex protects against concurrent first-init. Once initialized the
// verifier is reused for the lifetime of the Provider.
func (p *Provider) getVerifier(ctx context.Context) (*go_oidc.IDTokenVerifier, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.verifier != nil {
		return p.verifier, nil
	}

	// Inject the CA-aware HTTP client (if any) as a context value. go-oidc
	// honors it on both the discovery (NewProvider) and explicit-JWKS
	// (NewRemoteKeySet) paths.
	//
	// The verifier is memoized for the Provider's lifetime, so it outlives this
	// (request-scoped) ctx. That is safe because go-oidc's RemoteKeySet stores
	// the context as context.WithoutCancel(ctx) (oidc/jwks.go): it retains only
	// the values (our HTTP client) for later JWKS key refreshes, NOT the cancel
	// signal — so cancelling the first request cannot break future refreshes.
	// This depends on go-oidc >= the version that adopted WithoutCancel; a
	// downgrade would reintroduce a permanent fail-closed on key rotation
	// (regression-tested by TestProvider_KeyRefreshAfterInitContextCancelled).
	if p.cfg.HTTPClient != nil {
		ctx = go_oidc.ClientContext(ctx, p.cfg.HTTPClient)
	}

	cfg := &go_oidc.Config{
		SkipClientIDCheck:    true, // audience check is enforced in Verify against the route's allowlist
		SupportedSigningAlgs: slices.Clone(p.cfg.SupportedAlgs),
	}

	if p.cfg.JWKSURL != "" {
		keySet := go_oidc.NewRemoteKeySet(ctx, p.cfg.JWKSURL)
		p.verifier = go_oidc.NewVerifier(p.cfg.Issuer, keySet, cfg)
		return p.verifier, nil
	}

	pp, err := go_oidc.NewProvider(ctx, p.cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("identity/extjwt: discovery failed for %s: %w", p.cfg.Issuer, err)
	}
	p.verifier = pp.Verifier(cfg)
	return p.verifier, nil
}

// audienceMatches reports whether any element of `have` is also in `want`.
func audienceMatches(have, want []string) bool {
	for _, h := range have {
		if slices.Contains(want, h) {
			return true
		}
	}
	return false
}
