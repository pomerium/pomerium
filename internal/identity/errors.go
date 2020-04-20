package identity

import "errors"

// ErrRevokeNotImplemented error type when Revoke method is not implemented
// by an identity provider
var ErrRevokeNotImplemented = errors.New("revoke not implemented")

// ErrNoRevokeWithEndSessionURL error type when Revoke method is not implemented
// by a provider but the EndSessionURL is supplied.
var ErrNoRevokeWithEndSessionURL = errors.New("revoke not implemented, end session url exists")
