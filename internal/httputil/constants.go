package httputil // import "github.com/pomerium/pomerium/internal/httputil"

const (
	// HeaderPomeriumResponse is set when pomerium itself creates a response,
	// as opposed to the downstream application and can be used to distinguish
	// between an application error, and a pomerium related error when debugging.
	// Especially useful when working with single page apps (SPA).
	HeaderPomeriumResponse = "x-pomerium-intercepted-response"
)
