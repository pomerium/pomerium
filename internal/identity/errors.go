package identity

import "errors"

// ErrRevokeNotImplemented error type when Revoke method is not implemented
// by an identity provider
var ErrRevokeNotImplemented = errors.New("internal/identity: revoke not implemented")

// ErrSignoutNotImplemented error type when end session is not implemented
// by an identity provider
// https://openid.net/specs/openid-connect-frontchannel-1_0.html#RPInitiated
var ErrSignoutNotImplemented = errors.New("internal/identity: end session not implemented")
