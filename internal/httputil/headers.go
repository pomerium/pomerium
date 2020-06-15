package httputil

// AuthorizationTypePomerium is for Authorization: Pomerium JWT... headers
const AuthorizationTypePomerium = "Pomerium"

// Pomerium headers contain information added to a request.
const (
	// HeaderPomeriumResponse is set when pomerium itself creates a response,
	// as opposed to the downstream application and can be used to distinguish
	// between an application error, and a pomerium related error when debugging.
	// Especially useful when working with single page apps (SPA).
	HeaderPomeriumResponse = "x-pomerium-intercepted-response"
	// HeaderPomeriumJWTAssertion is the header key containing JWT signed user details.
	HeaderPomeriumJWTAssertion = "x-pomerium-jwt-assertion"
)

// HeadersContentSecurityPolicy are the content security headers added to the service's handlers
// by default includes profile photo exceptions for supported identity providers.
// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/script-src
var HeadersContentSecurityPolicy = map[string]string{
	"Content-Security-Policy": "default-src 'none'; style-src 'self' data:; img-src * data:;",
	"Referrer-Policy":         "Same-origin",
}

// Forward headers contains information from the client-facing side of proxy
// servers that is altered or lost when a proxy is involved in the path of the
// request.
//
// https://tools.ietf.org/html/rfc7239
// https://en.wikipedia.org/wiki/X-Forwarded-For
const (
	HeaderForwardedFor    = "X-Forwarded-For"
	HeaderForwardedHost   = "X-Forwarded-Host"
	HeaderForwardedMethod = "X-Forwarded-Method" // traefik
	HeaderForwardedPort   = "X-Forwarded-Port"
	HeaderForwardedProto  = "X-Forwarded-Proto"
	HeaderForwardedServer = "X-Forwarded-Server"
	HeaderForwardedURI    = "X-Forwarded-Uri"   // traefik
	HeaderOriginalMethod  = "X-Original-Method" // nginx
	HeaderOriginalURL     = "X-Original-Url"    // nginx
	HeaderRealIP          = "X-Real-Ip"
	HeaderSentFrom        = "X-Sent-From"
)

// HeadersXForwarded is the slice of the header keys used to contain information
// from the client-facing side of proxy servers that is altered or lost when a
// proxy is involved in the path of the request.
//
// https://tools.ietf.org/html/rfc7239
// https://en.wikipedia.org/wiki/X-Forwarded-For
var HeadersXForwarded = []string{
	HeaderForwardedFor,
	HeaderForwardedHost,
	HeaderForwardedMethod,
	HeaderForwardedPort,
	HeaderForwardedProto,
	HeaderForwardedServer,
	HeaderForwardedURI,
	HeaderOriginalMethod,
	HeaderOriginalURL,
	HeaderRealIP,
	HeaderSentFrom,
}

// PomeriumJWTHeaderName returns the header name set by pomerium for given JWT claim field.
func PomeriumJWTHeaderName(claim string) string {
	return "x-pomerium-claim-" + claim
}
