package provider

import "errors"

// ErrNotFound reports that the backend has no value for the ref. The resolver
// negative-caches this class of error; every other error is treated as
// transient (retried with backoff, never negative-cached).
var ErrNotFound = errors.New("secret not found")

// IsNotFound reports whether err is or wraps ErrNotFound.
func IsNotFound(err error) bool { return errors.Is(err, ErrNotFound) }
