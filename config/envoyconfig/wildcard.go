package envoyconfig

import "strings"

// Returns true if the given host contains a wildcard token and the wildcard
// token does not appear at the beginning nor the end of the host.
func isSpecialWildcardHost(host string) bool {
	l := len(host)
	if l <= 2 {
		return false
	}
	return strings.Contains(host[1:l-1], "*")
}
