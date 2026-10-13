package oidc

import (
	"context"
	"net/url"
)

type signInParamsKey struct{}

// WithSignInParams returns a context that makes SignIn add params to the
// authentication request it sends the user to, such as prompt=login or max_age
// when the user must re-authenticate. They take precedence over the provider's
// configured request parameters.
func WithSignInParams(ctx context.Context, params url.Values) context.Context {
	return context.WithValue(ctx, signInParamsKey{}, params)
}

// SignInParamsFromContext returns the params set by WithSignInParams.
func SignInParamsFromContext(ctx context.Context) url.Values {
	params, _ := ctx.Value(signInParamsKey{}).(url.Values)
	return params
}
