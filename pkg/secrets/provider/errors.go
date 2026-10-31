package provider

import "errors"

// Error taxonomy, as the resolver keys its caching decisions off it:
//
//   - ErrNotFound is negative-cached: the backend has no value and the
//     resolver waits out a negative TTL before asking again.
//   - Every other error, ErrTooLarge included, is transient: retried with
//     backoff, never negative-cached. The operator fixes the backend in place
//     and the next refresh recovers.

// ErrNotFound reports that the backend has no value for the ref.
var ErrNotFound = errors.New("secret not found")

// IsNotFound reports whether err is or wraps ErrNotFound.
func IsNotFound(err error) bool { return errors.Is(err, ErrNotFound) }

// ErrTooLarge reports that the backend payload exceeds the provider's size
// cap. Providers must return it instead of a truncated value: a cut-off secret
// is a valid-looking wrong value, which is worse than no value at all.
var ErrTooLarge = errors.New("secret too large")
