package urlutil

import "errors"

var (
	// ErrExpired indicates that token is used after expiry time indicated in exp claim.
	ErrExpired = errors.New("internal/urlutil: validation failed, url hmac is expired")

	// ErrIssuedInTheFuture indicates that the issued field is in the future.
	ErrIssuedInTheFuture = errors.New("internal/urlutil: validation field, url hmac issued in the future")

	// ErrNumericDateMalformed indicates a malformed unix timestamp was found while parsing.
	ErrNumericDateMalformed = errors.New("internal/urlutil: malformed unix timestamp field")
)
