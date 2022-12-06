package urlutil

import (
	"fmt"
	"net/url"
	"strconv"
	"time"
)

// BuildTimeParameters adds the issued and expiry timestamps to the query parameters.
func BuildTimeParameters(params url.Values, expiry time.Duration) {
	now := time.Now()

	params.Set(QueryIssued, fmt.Sprint(now.UnixMilli()))
	params.Set(QueryExpiry, fmt.Sprint(now.Add(expiry).UnixMilli()))
}

// ValidateTimeParameters validates that the issued and expiry timestamps in the query parameters are valid.
func ValidateTimeParameters(params url.Values) error {
	now := time.Now()

	issuedMS, err := strconv.ParseInt(params.Get(QueryIssued), 10, 64)
	if err != nil {
		return fmt.Errorf("invalid issued timestamp: %w", err)
	}
	issued := time.UnixMilli(issuedMS)

	if now.Add(DefaultLeeway).Before(issued) {
		return ErrIssuedInTheFuture
	}

	expiryMS, err := strconv.ParseInt(params.Get(QueryExpiry), 10, 64)
	if err != nil {
		return fmt.Errorf("invalid expiry timestamp: %w", err)
	}
	expiry := time.UnixMilli(expiryMS)

	if now.Add(-DefaultLeeway).After(expiry) {
		return ErrExpired
	}

	return nil
}
