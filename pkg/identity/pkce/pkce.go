package pkce

import (
	"context"
	"strings"

	"golang.org/x/oauth2"
)

// Params describes a PKCE verifier and method.
type Params struct {
	Verifier string
	Method   string
}

type pkceContextKey struct{}

// WithPKCE stores PKCE parameters on the context.
func WithPKCE(ctx context.Context, params Params) context.Context {
	return context.WithValue(ctx, pkceContextKey{}, params)
}

// FromContext extracts PKCE parameters from the context.
func FromContext(ctx context.Context) (Params, bool) {
	params, ok := ctx.Value(pkceContextKey{}).(Params)
	if !ok || params.Verifier == "" {
		return Params{}, false
	}
	return params, true
}

// MethodsProvider exposes supported PKCE methods from an IdP.
type MethodsProvider interface {
	PKCEMethods() []string
}

// AuthCodeOptions returns auth code options for PKCE.
// Only S256 is supported; PLAIN is intentionally not implemented per RFC 7636 §4.2.
func AuthCodeOptions(params Params) []oauth2.AuthCodeOption {
	if params.Verifier == "" || !strings.EqualFold(params.Method, "S256") {
		return nil
	}
	return []oauth2.AuthCodeOption{oauth2.S256ChallengeOption(params.Verifier)}
}

// VerifierOption returns an auth code option for the code verifier.
func VerifierOption(params Params) (oauth2.AuthCodeOption, bool) {
	if params.Verifier == "" {
		return nil, false
	}
	return oauth2.VerifierOption(params.Verifier), true
}
