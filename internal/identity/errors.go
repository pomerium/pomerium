package identity

import "errors"

// ErrRevokeNotImplemented error type when Revoke method is not implemented
// by an identity provider
var ErrRevokeNotImplemented = errors.New("revoke not implemented")

// ProviderError records an error and the message and provider involved.
type ProviderError struct {
	Provider string
	Source   string
	Err      error
}

func (e ProviderError) Error() string { return e.Source + " " + e.Provider + ": " + e.Err.Error() }
