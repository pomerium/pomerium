package httputil

import (
	"net/http"
	"strings"
)

// GetClientIP returns the client IP address from the request.
func GetClientIP(r *http.Request) string {
	if clientIP := r.Header.Get("X-Forwarded-For"); clientIP != "" {
		return strings.Split(clientIP, ",")[0]
	}
	return strings.Split(r.RemoteAddr, ":")[0]
}
