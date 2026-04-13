package providers

import (
	"net/http"

	"github.com/pomerium/pomerium/pkg/storage/blob/drivers"
)

// identityRoundTripper wraps an http.RoundTripper and appends the blob identity
// from the request context to the User-Agent header. This causes the identity
// to appear in cloud provider audit logs (e.g. GCS Cloud Audit Logs).
type identityRoundTripper struct {
	base http.RoundTripper
}

func (t *identityRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	identity, ok := drivers.BlobUserAgentFromContext(req.Context())
	if ok {
		req = req.Clone(req.Context())
		if ua := req.Header.Get("User-Agent"); ua != "" {
			req.Header.Set("User-Agent", ua+" "+identity)
		} else {
			req.Header.Set("User-Agent", identity)
		}
	}
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(req)
}
