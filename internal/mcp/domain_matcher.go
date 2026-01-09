package mcp

import (
	"errors"
	"fmt"
	"net/url"

	"github.com/caddyserver/certmagic"
)

// ErrDomainNotAllowed is returned when a client ID URL's domain is not in the allowed list.
var ErrDomainNotAllowed = errors.New("client_id domain not allowed")

// DomainMatcher checks if domains match against a list of allowed patterns.
type DomainMatcher struct {
	allowedDomains []string
}

// NewDomainMatcher creates a new DomainMatcher with the given allowed domain patterns.
// Patterns support wildcards like "*.example.com".
func NewDomainMatcher(allowedDomains []string) *DomainMatcher {
	return &DomainMatcher{allowedDomains: allowedDomains}
}

// IsAllowed checks if the given hostname matches any of the allowed domain patterns.
// Uses certmagic.MatchWildcard for wildcard pattern matching (e.g., "*.github.com").
func (m *DomainMatcher) IsAllowed(hostname string) bool {
	for _, pattern := range m.allowedDomains {
		if certmagic.MatchWildcard(hostname, pattern) {
			return true
		}
	}
	return false
}

// ValidateURLDomain checks if the URL's hostname is in the allowed domains list.
// Returns an error if the domain is not allowed.
func (m *DomainMatcher) ValidateURLDomain(u *url.URL) error {
	hostname := u.Hostname()
	if !m.IsAllowed(hostname) {
		return fmt.Errorf("%w: %q is not in allowed domains", ErrDomainNotAllowed, hostname)
	}
	return nil
}
