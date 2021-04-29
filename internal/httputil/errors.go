package httputil

import (
	"html/template"
	"net/http"
	"net/url"

	"github.com/pomerium/pomerium/internal/frontend"
	"github.com/pomerium/pomerium/internal/telemetry/requestid"
)

var errorTemplate = template.Must(frontend.NewTemplates())

// HTTPError contains an HTTP status code and wrapped error.
type HTTPError struct {
	// HTTP status codes as registered with IANA.
	Status int
	// Err is the wrapped error.
	Err error
	// DebugURL is the URL to the debug endpoint.
	DebugURL *url.URL
	// The request ID.
	RequestID string
}

// NewError returns an error that contains a HTTP status and error.
func NewError(status int, err error) error {
	return &HTTPError{Status: status, Err: err}
}

// Error implements the `error` interface.
func (e *HTTPError) Error() string {
	return http.StatusText(e.Status) + ": " + e.Err.Error()
}

// Unwrap implements the `error` Unwrap interface.
func (e *HTTPError) Unwrap() error { return e.Err }

// ErrorResponse replies to the request with the specified error message and HTTP code.
// It does not otherwise end the request; the caller should ensure no further
// writes are done to w.
func (e *HTTPError) ErrorResponse(w http.ResponseWriter, r *http.Request) {
	reqID := e.RequestID
	if e.RequestID == "" {
		// if empty, try to grab from the request id from the request context
		reqID = requestid.FromContext(r.Context())
	}
	response := struct {
		Status     int
		Error      string
		StatusText string   `json:"-"`
		RequestID  string   `json:",omitempty"`
		CanDebug   bool     `json:"-"`
		Version    string   `json:"-"`
		DebugURL   *url.URL `json:",omitempty"`
	}{
		Status:     e.Status,
		StatusText: http.StatusText(e.Status),
		Error:      e.Error(),
		RequestID:  reqID,
		CanDebug:   e.Status/100 == 4 && (e.DebugURL != nil || reqID != ""),
		DebugURL:   e.DebugURL,
	}
	// indicate to clients that the error originates from Pomerium, not the app
	w.Header().Set(HeaderPomeriumResponse, "true")

	if r.Header.Get("Accept") == "application/json" {
		RenderJSON(w, e.Status, response)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=UTF-8")
	w.WriteHeader(e.Status)
	errorTemplate.ExecuteTemplate(w, "error.html", response)
}
