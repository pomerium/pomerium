package httputil // import "github.com/pomerium/pomerium/internal/httputil"

const (
	// HeaderPomeriumResponse is set when pomerium itself creates a response,
	// as opposed to the downstream application and can be used to distinguish
	// between an application error, and a pomerium related error when debugging.
	// Especially useful when working with single page apps (SPA).
	HeaderPomeriumResponse = "x-pomerium-intercepted-response"
)

// HeadersContentSecurityPolicy are the content security headers added to the service's handlers
// by default includes profile photo exceptions for supported identity providers.
// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/script-src
var HeadersContentSecurityPolicy = map[string]string{
	"Content-Security-Policy": "default-src 'none'; style-src 'self'; img-src *;",
	"Referrer-Policy":         "Same-origin",
}
