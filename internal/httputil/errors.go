package httputil // import "github.com/pomerium/pomerium/internal/httputil"

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/templates"
)

// Error reports an http error, its http status code, a custom message, and
// whether it is CanDebug.
type Error struct {
	Message    string
	Code       int
	CanDebug   bool
	InnerError error
}

// Error fulfills the error interface, returning a string representation of the error.
func (e Error) Error() string {
	return fmt.Sprintf("%d %s: %s", e.Code, http.StatusText(e.Code), e.Message)
}

func (e *Error) Log(r *http.Request) {
	log.FromRequest(r).Error().
		Err(e.InnerError).
		Str("error-message", e.Message).
		Bool("error-debugable", e.CanDebug).
		Int("error-code", e.Code).
		Str("error-text", http.StatusText(e.Code)).
		Msg(e.Error())
}

// ErrorResponse renders an error page for errors given a message and a status code.
// If no message is passed, defaults to the text of the status code.
func ErrorResponse(rw http.ResponseWriter, r *http.Request, e *Error) {
	e.Log(r)
	var requestID string
	if id, ok := log.IDFromRequest(r); ok {
		requestID = id
	}
	if r.Header.Get("Accept") == "application/json" {
		var response struct {
			Error string `json:"error"`
		}
		response.Error = e.Message
		writeJSONResponse(rw, e.Code, response)
	} else {
		rw.WriteHeader(e.Code)
		t := struct {
			Code      int
			Title     string
			Message   string
			RequestID string
			CanDebug  bool
		}{
			Code:      e.Code,
			Title:     http.StatusText(e.Code),
			Message:   e.Message,
			RequestID: requestID,
			CanDebug:  e.CanDebug,
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
