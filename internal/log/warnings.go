package log

import (
	"sync"

	"github.com/pomerium/pomerium/internal/syncutil"
)

var warnCookieSecretOnce sync.Once

// WarnCookieSecret warns about the cookie secret.
func WarnCookieSecret() {
	warnCookieSecretOnce.Do(func() {
		Info().
			Msg("using a generated COOKIE_SECRET. " +
				"Set the COOKIE_SECRET to avoid users being logged out on restart. " +
				"https://www.pomerium.com/docs/reference/cookie-secret")
	})
}

var warnNoTLSCertificateOnce syncutil.OnceMap[string]

// WarnNoTLSCertificate warns about no TLS certificate.
func WarnNoTLSCertificate(domain string) {
	warnNoTLSCertificateOnce.Do(domain, func() {
		Info().
			Str("domain", domain).
			Msg("no TLS certificate found for domain, using a self-signed certificate")
	})
}

var warnWebSocketHTTP1_1Once syncutil.OnceMap[string]

// WarnWebSocketHTTP1_1 warns about falling back to http 1.1 due to web socket support.
func WarnWebSocketHTTP1_1(clusterID string) {
	warnWebSocketHTTP1_1Once.Do(clusterID, func() {
		Info().
			Str("cluster-id", clusterID).
			Msg("forcing http/1.1 due to web socket support")
	})
}
