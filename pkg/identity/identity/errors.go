package identity

import "errors"

// well known errors
var (
	ErrVerifyAccessTokenNotSupported   = errors.New("identity: access token verification not supported")
	ErrVerifyIdentityTokenNotSupported = errors.New("identity: identity token verification not supported")
)
