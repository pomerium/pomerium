package urlutil

import "net/url"

// Redacted removes all upstream URL userinfo while preserving the rest of the
// URL for presentation. url.URL.Redacted keeps the username, which is unsafe
// for token-in-username configurations and other credential-bearing userinfo.
func Redacted(u *url.URL) string {
	if u == nil {
		return ""
	}
	if u.User == nil {
		return u.String()
	}
	cp := *u
	cp.User = url.User("xxxxx")
	return cp.String()
}
