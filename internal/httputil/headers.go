package httputil

// Pomerium authorization types
const (
	// AuthorizationTypePomerium is for Authorization: Pomerium JWT... headers
	AuthorizationTypePomerium                 = "Pomerium"
	AuthorizationTypePomeriumIDPAccessToken   = "Pomerium-IDP-Access-Token"   //nolint: gosec
	AuthorizationTypePomeriumIDPIdentityToken = "Pomerium-IDP-Identity-Token" //nolint: gosec
)

// Standard headers
const (
	HeaderAuthorization    = "Authorization"
	HeaderReferrer         = "Referer"
	HeaderImpersonateGroup = "Impersonate-Group"
	HeaderUpgrade          = "Upgrade"
)

// Pomerium headers contain information added to a request.
const (
	// HeaderPomeriumAuthorization is the header key for a pomerium authorization JWT. It
	// can be used in place of the standard authorization header if that header is being
	// used by upstream applications.
	HeaderPomeriumAuthorization    = "x-pomerium-authorization"
	HeaderPomeriumIDPAccessToken   = "x-pomerium-idp-access-token"   //nolint: gosec
	HeaderPomeriumIDPIdentityToken = "x-pomerium-idp-identity-token" //nolint: gosec
	// HeaderPomeriumResponse is set when pomerium itself creates a response,
	// as opposed to the upstream application and can be used to distinguish
	// between an application error, and a pomerium related error when debugging.
	// Especially useful when working with single page apps (SPA).
	HeaderPomeriumResponse = "x-pomerium-intercepted-response"
	// HeaderPomeriumJWTAssertion is the header key containing JWT signed user details.
	HeaderPomeriumJWTAssertion = "x-pomerium-jwt-assertion"
	// HeaderPomeriumJWTAssertionFor carries over original user identity from a chain of network calls.
	HeaderPomeriumJWTAssertionFor = "x-pomerium-jwt-assertion-for"
	// HeaderPomeriumReproxyPolicy is the header key containing the policy to reproxy a request to.
	HeaderPomeriumReproxyPolicy = "x-pomerium-reproxy-policy"
	// HeaderPomeriumReproxyPolicyHMAC is an HMAC of the HeaderPomeriumReproxyPolicy header.
	HeaderPomeriumReproxyPolicyHMAC = "x-pomerium-reproxy-policy-hmac"
	// HeaderPomeriumRoutingKey is a string used for routing user requests to a consistent upstream server.
	HeaderPomeriumRoutingKey = "x-pomerium-routing-key"
)

// HeadersContentSecurityPolicy are the content security headers added to the service's handlers
// by default includes profile photo exceptions for supported identity providers.
// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/script-src
var HeadersContentSecurityPolicy = map[string]string{
	"Content-Security-Policy": "default-src 'none'; style-src 'self' 'unsafe-inline' data:; img-src * data:; script-src 'self' 'unsafe-inline'; font-src data:",
	"Referrer-Policy":         "Same-origin",
}

// PomeriumJWTHeaderName returns the header name set by pomerium for given JWT claim field.
func PomeriumJWTHeaderName(claim string) string {
	return "x-pomerium-claim-" + claim
}
