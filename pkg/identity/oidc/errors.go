package oidc

import (
	"errors"
)

// ErrRevokeNotImplemented is returned when revoke is not implemented
// by an identity provider.
var ErrRevokeNotImplemented = errors.New("identity/oidc: revoke not implemented")

// ErrSignoutNotImplemented is returned when end session is not implemented
// by an identity provider
// https://openid.net/specs/openid-connect-frontchannel-1_0.html#RPInitiated
var ErrSignoutNotImplemented = errors.New("identity/oidc: end session not implemented")

// ErrMissingProviderURL is returned when an identity provider requires a provider url
// does not receive one.
var ErrMissingProviderURL = errors.New("identity/oidc: missing provider url")

// ErrMissingIDToken is returned when (usually on refresh) and identity provider
// failed to include an id_token in a oauth2 token.
var ErrMissingIDToken = errors.New("identity/oidc: missing id_token")

// ErrMissingRefreshToken is returned if no refresh token was found.
var ErrMissingRefreshToken = errors.New("identity/oidc: missing refresh token")

// ErrMissingAccessToken is returned when no access token was found.
var ErrMissingAccessToken = errors.New("identity/oidc: missing access token")
