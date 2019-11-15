package httputil // import "github.com/pomerium/pomerium/internal/httputil"

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/templates"
)

// Error formats creates a HTTP error with code, user friendly (and safe) error
// message. If nil or empty, HTTP status code defaults to 500 and message
// defaults to the text of the status code.
func Error(message string, code int, err error) error {
	if code == 0 {
		code = http.StatusInternalServerError
	}
	if message == "" {
		message = http.StatusText(code)
	}
	return &httpError{Message: message, Code: code, Err: err}
}

type httpError struct {
	// Message to present to the end user.
	Message string
	// HTTP status codes as registered with IANA.
	Code int

	Err error // the cause
}

func (e *httpError) Error() string {
	s := fmt.Sprintf("%d %s: %s", e.Code, http.StatusText(e.Code), e.Message)
	if e.Err != nil {
		return s + ": " + e.Err.Error()
	}
	return s
}
func (e *httpError) Unwrap() error { return e.Err }

// Timeout reports whether this error represents a user debuggable error.
func (e *httpError) Debugable() bool {
	return e.Code == http.StatusUnauthorized || e.Code == http.StatusForbidden
}

// ErrorResponse renders an error page given an error. If the error is a
// http error from this package, a user friendly message is set, http status code,
// the ability to debug are also set.
func ErrorResponse(w http.ResponseWriter, r *http.Request, e error) {
	statusCode := http.StatusInternalServerError // default status code to return
	errorString := e.Error()
	var canDebug bool
	var requestID string
	var httpError *httpError
	// if this is an HTTPError, we can add some additional useful information
	if errors.As(e, &httpError) {
		canDebug = httpError.Debugable()
		statusCode = httpError.Code
		errorString = httpError.Message
	}

	// indicate to clients that the error originates from Pomerium, not the app
	w.Header().Set(HeaderPomeriumResponse, "true")

	log.FromRequest(r).Error().Err(e).Str("http-message", errorString).Int("http-code", statusCode).Msg("http-error")

	if id, ok := log.IDFromRequest(r); ok {
		requestID = id
	}
	if r.Header.Get("Accept") == "application/json" {
		var response struct {
			Error string `json:"error"`
		}
		response.Error = errorString
		writeJSONResponse(w, statusCode, response)
	} else {
		w.WriteHeader(statusCode)
		t := struct {
			Code      int
			Title     string
			Message   string
			RequestID string
			CanDebug  bool
		}{
			Code:      statusCode,
			Title:     http.StatusText(statusCode),
			Message:   errorString,
			RequestID: requestID,
			CanDebug:  canDebug,
		}
		templates.New().ExecuteTemplate(w, "error.html", t)
	}
}

// writeJSONResponse is a helper that sets the application/json header and writes a response.
func writeJSONResponse(w http.ResponseWriter, code int, response interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)

	err := json.NewEncoder(w).Encode(response)
	if err != nil {
		io.WriteString(w, err.Error())
	}
}
