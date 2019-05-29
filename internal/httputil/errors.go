package httputil // import "github.com/pomerium/pomerium/internal/httputil"

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/templates"
)

// HTTPError stores the status code and a message for a given HTTP error.
type HTTPError struct {
	Code    int
	Message string
}

// Error fulfills the error interface, returning a string representation of the error.
func (h HTTPError) Error() string {
	return fmt.Sprintf("%d %s: %s", h.Code, http.StatusText(h.Code), h.Message)
}

// CodeForError maps an error type and returns a corresponding http.Status
func CodeForError(err error) int {
	switch err {
	case ErrTokenRevoked:
		return http.StatusUnauthorized
	}
	return http.StatusInternalServerError
}

// ErrorResponse renders an error page for errors given a message and a status code.
// If no message is passed, defaults to the text of the status code.
func ErrorResponse(rw http.ResponseWriter, r *http.Request, message string, code int) {
	if message == "" {
		message = http.StatusText(code)
	}
	reqID := ""
	id, ok := log.IDFromRequest(r)
	if ok {
		reqID = id
	}
	if r.Header.Get("Accept") == "application/json" {
		var response struct {
			Error string `json:"error"`
		}
		response.Error = message
		writeJSONResponse(rw, code, response)
	} else {
		title := http.StatusText(code)
		rw.WriteHeader(code)
		t := struct {
			Code      int
			Title     string
			Message   string
			RequestID string
		}{
			Code:      code,
			Title:     title,
			Message:   message,
			RequestID: reqID,
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
