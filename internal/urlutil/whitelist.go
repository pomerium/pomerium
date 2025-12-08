package urlutil

import (
	"net"
	"net/url"
)

// IsRedirectAllowed returns true if the redirect URL is whitelisted.
func IsRedirectAllowed(redirectURL *url.URL, whitelistDomains []string) bool {
	if redirectURL.Scheme != "http" && redirectURL.Scheme != "https" {
		return false
	}
	for _, domain := range whitelistDomains {
		if domain == "localhost" && IsLoopback(redirectURL) {
			return true
		} else if redirectURL.Hostname() == domain {
			return true
		}
	}
	return false
}

// IsLoopback returns true if the given URL corresponds with a loopback address.
func IsLoopback(u *url.URL) bool {
	hostname := u.Hostname()
	if hostname == "localhost" {
		return true
	}

	if ip := net.ParseIP(hostname); ip != nil {
		return ip.IsLoopback()
	}

	return false
}
