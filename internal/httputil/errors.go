package httputil

import (
	"encoding/json"
	"errors"
	"html/template"
	"net/http"

	"github.com/pomerium/pomerium/internal/frontend"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/internal/version"
)

var ErrRedirectOnly = errors.New("httputil: redirecting to authenticate service")

var errorTemplate = template.Must(frontend.NewTemplates())
var fullVersion = version.FullVersion()

// HTTPError contains an HTTP status code and wrapped error.
type HTTPError struct {
	// HTTP status codes as registered with IANA.
	Status int
	// Err is the wrapped error
	Err error
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

// Debugable reports whether this error represents a user debuggable error.
func (e *HTTPError) Debugable() bool {
	return e.Status == http.StatusUnauthorized || e.Status == http.StatusForbidden
}

// RetryURL returns the requests intended destination, if any.
func (e *HTTPError) RetryURL(r *http.Request) string {
	return r.FormValue(urlutil.QueryRedirectURI)
}

type errResponse struct {
	Status int
	Error  string

	StatusText string `json:"-"`
	RequestID  string `json:",omitempty"`
	CanDebug   bool   `json:"-"`
	RetryURL   string `json:"-"`
	Version    string `json:"-"`
}

// ErrorResponse replies to the request with the specified error message and HTTP code.
// It does not otherwise end the request; the caller should ensure no further
// writes are done to w.
func (e *HTTPError) ErrorResponse(w http.ResponseWriter, r *http.Request) {
	log.FromRequest(r).Info().Err(e).Msg("httputil: ErrorResponse")
	if errors.Is(e, ErrRedirectOnly) {
		return
	}
	// indicate to clients that the error originates from Pomerium, not the app
	w.Header().Set(HeaderPomeriumResponse, "true")
	w.WriteHeader(e.Status)

	var requestID string
	if id, ok := log.IDFromRequest(r); ok {
		requestID = id
	}
	response := errResponse{
		Status:     e.Status,
		StatusText: http.StatusText(e.Status),
		Error:      e.Error(),
		RequestID:  requestID,
		CanDebug:   e.Debugable(),
		RetryURL:   e.RetryURL(r),
		Version:    fullVersion,
	}

	if r.Header.Get("Accept") == "application/json" {
		w.Header().Set("Content-Type", "application/json")
		err := json.NewEncoder(w).Encode(response)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	} else {
		w.Header().Set("Content-Type", "text/html; charset=UTF-8")
		errorTemplate.ExecuteTemplate(w, "error.html", response)
	}
}
