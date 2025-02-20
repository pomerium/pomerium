package identity

import "github.com/pomerium/pomerium/pkg/identity/identity"

// re-exported errors
var (
	ErrVerifyAccessTokenNotSupported   = identity.ErrVerifyAccessTokenNotSupported
	ErrVerifyIdentityTokenNotSupported = identity.ErrVerifyIdentityTokenNotSupported
)
