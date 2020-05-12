package requestid

import "net/http"

type transport struct {
	base http.RoundTripper
}

// NewRoundTripper creates a new RoundTripper which adds the request id to the outgoing headers.
func NewRoundTripper(base http.RoundTripper) http.RoundTripper {
	return &transport{base: base}
}

func (t *transport) RoundTrip(req *http.Request) (res *http.Response, err error) {
	requestID := FromContext(req.Context())
	if requestID != "" && req.Header.Get(headerName) == "" {
		req.Header.Set(headerName, requestID)
	}

	return t.base.RoundTrip(req)
}

type httpMiddleware struct {
	next http.Handler
}

// HTTPMiddleware creates a new http middleware that populates the request id.
func HTTPMiddleware() func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return httpMiddleware{next: next}
	}
}

func (h httpMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	requestID := FromHTTPHeader(r.Header)
	if requestID == "" {
		requestID = New()
	}
	ctx := WithValue(r.Context(), requestID)
	r = r.WithContext(ctx)
	h.next.ServeHTTP(w, r)
}

// FromHTTPHeader returns the request id in the HTTP header. If no request id exists,
// an empty string is returned.
func FromHTTPHeader(hdr http.Header) string {
	return hdr.Get(headerName)
}
