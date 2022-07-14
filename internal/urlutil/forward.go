package urlutil

import (
	"net/http"
	"net/url"
	"strings"
)

// Forward headers contains information from the client-facing side of proxy
// servers that is altered or lost when a proxy is involved in the path of the
// request.
//
// https://tools.ietf.org/html/rfc7239
// https://en.wikipedia.org/wiki/X-Forwarded-For
const (
	HeaderForwardedHost  = "X-Forwarded-Host"
	HeaderForwardedProto = "X-Forwarded-Proto"
	HeaderForwardedURI   = "X-Forwarded-Uri" // traefik
	HeaderOriginalURL    = "X-Original-Url"  // nginx
)

// GetForwardAuthURL gets the forward-auth URL for the given request.
func GetForwardAuthURL(r *http.Request) *url.URL {
	urqQuery := r.URL.Query().Get("uri")
	u, _ := ParseAndValidateURL(urqQuery)
	if u == nil {
		u = &url.URL{
			Scheme: r.Header.Get(HeaderForwardedProto),
			Host:   r.Header.Get(HeaderForwardedHost),
		}
		rawPath := r.Header.Get(HeaderForwardedURI)
		if idx := strings.Index(rawPath, "?"); idx >= 0 {
			u.Path = rawPath[:idx]
			u.RawQuery = rawPath[idx+1:]
		} else {
			u.Path = rawPath
		}
	}
	originalURL := r.Header.Get(HeaderOriginalURL)
	if originalURL != "" {
		k, _ := ParseAndValidateURL(originalURL)
		if k != nil {
			u = k
		}
	}
	return u
}
