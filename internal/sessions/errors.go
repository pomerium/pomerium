package sessions

import (
	"errors"
)

var (
	// ErrNoSessionFound is the error for when no session is found.
	ErrNoSessionFound = errors.New("internal/sessions: session is not found")

	// ErrInvalidSession is the error for when a session is invalid.
	ErrInvalidSession = errors.New("internal/sessions: invalid session")

	// ErrMalformed is the error for when a session is found but is malformed.
	ErrMalformed = errors.New("internal/sessions: session is malformed")

	// ErrNotValidYet indicates that token is used before time indicated in nbf claim.
	ErrNotValidYet = errors.New("internal/sessions: validation failed, token not valid yet (nbf)")

	// ErrExpired indicates that token is used after expiry time indicated in exp claim.
	ErrExpired = errors.New("internal/sessions: validation failed, token is expired (exp)")

	// ErrExpiryRequired indicates that the token does not contain a valid expiry (exp) claim.
	ErrExpiryRequired = errors.New("internal/sessions: validation failed, token expiry (exp) is required")

	// ErrIssuedInTheFuture indicates that the iat field is in the future.
	ErrIssuedInTheFuture = errors.New("internal/sessions: validation field, token issued in the future (iat)")

	// ErrInvalidAudience indicated invalid aud claim.
	ErrInvalidAudience = errors.New("internal/sessions: validation failed, invalid audience claim (aud)")
)
