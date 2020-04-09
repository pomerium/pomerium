package identity

import "errors"

// ErrRevokeNotImplemented error type when Revoke method is not implemented
// by an identity provider
var ErrRevokeNotImplemented = errors.New("revoke not implemented")
