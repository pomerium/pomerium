package httputil // import "github.com/pomerium/pomerium/internal/httputil"

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"golang.org/x/xerrors"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/templates"
)

// Error formats creates a HTTP error with code, user friendly (and safe) error
// message. If nil or empty:
// HTTP status code defaults to 500.
// Message defaults to the text of the status code.
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
func (e *httpError) Debugable() bool { return e.Code == http.StatusUnauthorized }

// ErrorResponse renders an error page given an error. If the error is a
// http error from this package, a user friendly message is set, http status code,
// the ability to debug are also set.
func ErrorResponse(rw http.ResponseWriter, r *http.Request, e error) {
	statusCode := http.StatusInternalServerError // default status code to return
	errorString := e.Error()
	var canDebug bool
	var requestID string
	var httpError *httpError
	// if this is an HTTPError, we can add some additional useful information
	if xerrors.As(e, &httpError) {
		canDebug = httpError.Debugable()
		statusCode = httpError.Code
		errorString = httpError.Message
	}
	log.FromRequest(r).Error().Err(e).Str("http-message", errorString).Int("http-code", statusCode).Msg("http-error")

	if id, ok := log.IDFromRequest(r); ok {
		requestID = id
	}
	if r.Header.Get("Accept") == "application/json" {
		var response struct {
			Error string `json:"error"`
		}
		response.Error = e.Error()
		writeJSONResponse(rw, statusCode, response)
	} else {
		rw.WriteHeader(statusCode)
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
		templates.New().ExecuteTemplate(rw, "error.html", t)
	}
}

// writeJSONResponse is a helper that sets the application/json header and writes a response.
func writeJSONResponse(rw http.ResponseWriter, code int, response interface{}) {
	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(code)

	err := json.NewEncoder(rw).Encode(response)
	if err != nil {
		io.WriteString(rw, err.Error())
	}
}
