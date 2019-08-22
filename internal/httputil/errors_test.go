package httputil

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestErrorResponse(t *testing.T) {
	tests := []struct {
		name string
		rw   http.ResponseWriter
		r    *http.Request
		e    *httpError
	}{
		{"good", httptest.NewRecorder(), &http.Request{Method: http.MethodGet}, &httpError{Code: http.StatusBadRequest, Message: "missing id token"}},
		{"good json", httptest.NewRecorder(), &http.Request{Method: http.MethodGet, Header: http.Header{"Accept": []string{"application/json"}}}, &httpError{Code: http.StatusBadRequest, Message: "missing id token"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ErrorResponse(tt.rw, tt.r, tt.e)
		})
	}
}

func TestError_Error(t *testing.T) {

	tests := []struct {
		name     string
		Message  string
		Code     int
		InnerErr error
		want     string
	}{
		{"good", "short and stout", http.StatusTeapot, nil, "418 I'm a teapot: short and stout"},
		{"nested error", "short and stout", http.StatusTeapot, errors.New("another error"), "418 I'm a teapot: short and stout: another error"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := httpError{
				Message: tt.Message,
				Code:    tt.Code,
				Err:     tt.InnerErr,
			}
			if got := h.Error(); got != tt.want {
				t.Errorf("Error.Error() = %v, want %v", got, tt.want)
			}
		})
	}
}
