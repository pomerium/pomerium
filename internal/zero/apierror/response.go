// Package apierror provides a consistent way to handle errors from API calls
package apierror

import (
	"fmt"
	"net/http"
)

// CheckResponse checks the response for errors and returns the value or an error
func CheckResponse[T any](resp APIResponse[T], err error) (*T, error) {
	if err != nil {
		return nil, err
	}

	value := resp.GetValue()
	if value != nil {
		return value, nil
	}

	//nolint:bodyclose
	return nil, WithRequestID(responseError(resp), resp.GetHTTPResponse().Header)
}

// APIResponse is the interface that wraps the response from an API call
type APIResponse[T any] interface {
	// GetHTTPResponse returns the HTTP response
	GetHTTPResponse() *http.Response
	// GetInternalServerError returns the internal server error
	GetInternalServerError() (string, bool)
	// GetBadRequestError returns the bad request error
	GetBadRequestError() (string, bool)
	// GetValue returns the value
	GetValue() *T
}

// Error is the interface that wraps the error returned from an API call
type Error interface {
	GetError() string
}

func responseError[T any](resp APIResponse[T]) error {
	reason, ok := resp.GetBadRequestError()
	if ok {
		return NewTerminalError(fmt.Errorf("bad request: %v", reason))
	}
	reason, ok = resp.GetInternalServerError()
	if ok {
		return fmt.Errorf("internal server error: %v", reason)
	}

	if f, ok := resp.(interface{ GetForbiddenError() (string, bool) }); ok {
		if reason, ok := f.GetForbiddenError(); ok {
			return fmt.Errorf("forbidden: %v", reason)
		}
	}

	if f, ok := resp.(interface{ GetNotFoundError() (string, bool) }); ok {
		if reason, ok := f.GetNotFoundError(); ok {
			return fmt.Errorf("not found: %v", reason)
		}
	}

	//nolint:bodyclose
	httpResp := resp.GetHTTPResponse()
	if httpResp == nil {
		return fmt.Errorf("unexpected response: nil")
	}
	return fmt.Errorf("unexpected response: %v", httpResp.StatusCode)
}
