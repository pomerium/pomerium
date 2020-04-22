package oidc

import "errors"

// ErrRevokeNotImplemented error type when Revoke method is not implemented
// by an identity provider
var ErrRevokeNotImplemented = errors.New("identity/oidc: revoke not implemented")

// ErrSignoutNotImplemented error type when end session is not implemented
// by an identity provider
// https://openid.net/specs/openid-connect-frontchannel-1_0.html#RPInitiated
var ErrSignoutNotImplemented = errors.New("identity/oidc: end session not implemented")

// ErrMissingProviderURL is returned when an identity provider requires a provider url
// does not receive one.
var ErrMissingProviderURL = errors.New("identity/oidc: missing provider url")
