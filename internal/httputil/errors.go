package httputil // import "github.com/pomerium/pomerium/internal/httputil"

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/templates"
	"golang.org/x/xerrors"
)

// NewHTTPError returns an error for a given HTTP error.
func NewHTTPError(message string, code int) error {
	if code == 0 {
		code = http.StatusInternalServerError
	}
	if message == "" {
		message = http.StatusText(code)
	}
	return &httpError{Message: message, Code: code}
}

// WrappedHTTPError returns an error for a given HTTP error.
func WrappedHTTPError(message string, code int, err error) error {
	if code == 0 {
		code = http.StatusInternalServerError
	}
	if message == "" {
		message = http.StatusText(code)
	}
	return &httpError{Message: message, Code: code, Err: err}
}

// Error reports an http error, its http status code, a custom message, and
// whether it is CanDebug.
type httpError struct {
	// Message to present to the end user.
	Message string
	// HTTP status codes as registered with IANA.
	// See: https://www.iana.org/assignments/http-status-codes/http-status-codes.xhtml
	Code int

	// Err is the wrapped error
	Err error
}

// Error fulfills the error interface, returning a string representation of the error.
func (e *httpError) Error() string {
	s := fmt.Sprintf("%d %s: %s", e.Code, http.StatusText(e.Code), e.Message)
	if e.Err != nil {
		return s + ": " + e.Err.Error()
	}
	return s
}
func (e *httpError) Unwrap() error { return e.Err }

func (e *httpError) Debugable() bool { return e.Code == http.StatusUnauthorized }

func (e *httpError) Log(r *http.Request) {
	log.FromRequest(r).Error().Err(e.Err).Str("message", e.Message).Int("code", e.Code).Msg("http-error")
}

// ErrorResponse renders an error page given an error. If the underlying error is a
// http error from this package, a user friendly message is set, as is a status code,
// the ability to debug, and an additional log message.
func ErrorResponse(rw http.ResponseWriter, r *http.Request, e error) {
	statusCode := http.StatusInternalServerError // default status code to return
	var errorString string
	var canDebug bool
	var requestID string
	var httpError *httpError
	// if this is an HTTPError
	if xerrors.As(e, &httpError) {
		httpError.Log(r)
		canDebug = httpError.Debugable()
		statusCode = httpError.Code
		errorString = httpError.Message
	}
	log.FromRequest(r).Error().Err(e).Str("message", errorString).Int("code", statusCode).Msg("http-error")

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
