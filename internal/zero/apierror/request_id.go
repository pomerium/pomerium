package apierror

import (
	"fmt"
	"net/http"
)

// RequestIDError is an error that wraps another error and includes the response ID
type RequestIDError struct {
	Err        error
	ResponseID *string
}

// Error implements error for RequestIDError
func (e *RequestIDError) Error() string {
	if e.ResponseID == nil {
		return e.Err.Error()
	}
	return fmt.Sprintf("[x-response-id:%s]: %v", *e.ResponseID, e.Err)
}

// Unwrap implements errors.Unwrap for RequestIDError
func (e *RequestIDError) Unwrap() error {
	return e.Err
}

// Is implements errors.Is for RequestIDError
func (e *RequestIDError) Is(err error) bool {
	//nolint:errorlint
	_, ok := err.(*RequestIDError)
	return ok
}

// WithRequestID creates a new RequestIDError
func WithRequestID(err error, headers http.Header) *RequestIDError {
	r := &RequestIDError{Err: err}
	id := headers.Get("X-Response-Id")
	if id != "" {
		r.ResponseID = &id
	}
	return r
}
