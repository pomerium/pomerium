package httputil

import (
	"context"
	"net/http"
	"net/url"

	"github.com/pomerium/pomerium/internal/telemetry/requestid"
	"github.com/pomerium/pomerium/pkg/contextutil"
	"github.com/pomerium/pomerium/ui"
)

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
	str := StatusText(e.Status)
	if e.Err != nil {
		str += ": " + e.Err.Error()
	}
	return str
}

// Unwrap implements the `error` Unwrap interface.
func (e *HTTPError) Unwrap() error { return e.Err }

// ErrorResponse replies to the request with the specified error message and HTTP code.
// It does not otherwise end the request; the caller should ensure no further
// writes are done to w.
func (e *HTTPError) ErrorResponse(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	reqID := e.RequestID
	if e.RequestID == "" {
		// if empty, try to grab from the request id from the request context
		reqID = requestid.FromContext(r.Context())
	}
	response := struct {
		Status                 int
		Error                  string
		StatusText             string                              `json:"-"`
		RequestID              string                              `json:",omitempty"`
		CanDebug               bool                                `json:"-"`
		DebugURL               *url.URL                            `json:",omitempty"`
		PolicyEvaluationTraces []contextutil.PolicyEvaluationTrace `json:"policy_evaluation_traces"`
	}{
		Status:                 e.Status,
		StatusText:             StatusText(e.Status),
		Error:                  e.Error(),
		RequestID:              reqID,
		CanDebug:               e.Status/100 == 4 && (e.DebugURL != nil || reqID != ""),
		DebugURL:               e.DebugURL,
		PolicyEvaluationTraces: contextutil.GetPolicyEvaluationTraces(ctx),
	}
	// indicate to clients that the error originates from Pomerium, not the app
	w.Header().Set(HeaderPomeriumResponse, "true")

	if r.Header.Get("Accept") == "application/json" {
		RenderJSON(w, e.Status, response)
		return
	}

	m := map[string]interface{}{
		"canDebug":               response.CanDebug,
		"error":                  response.Error,
		"requestId":              response.RequestID,
		"status":                 response.Status,
		"statusText":             response.StatusText,
		"policyEvaluationTraces": response.PolicyEvaluationTraces,
	}
	if response.DebugURL != nil {
		m["debugUrl"] = response.DebugURL.String()
	}

	w.Header().Set("Content-Type", "text/html; charset=UTF-8")
	w.WriteHeader(response.Status)
	if err := ui.ServePage(w, r, "Error", m); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
