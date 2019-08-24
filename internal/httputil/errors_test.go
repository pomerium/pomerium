package httputil

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/go-cmp/cmp"
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
			got := h.Error()
			if diff := cmp.Diff(got, tt.want); diff != "" {
				t.Errorf("Error.Error() = %s", diff)
			}
		})
	}
}

func Test_httpError_Error(t *testing.T) {
	tests := []struct {
		name    string
		message string
		code    int
		err     error
		want    string
	}{
		{"good", "foobar", 200, nil, "200 OK: foobar"},
		{"no code", "foobar", 0, nil, "500 Internal Server Error: foobar"},
		{"no message or code", "", 0, nil, "500 Internal Server Error: Internal Server Error"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := Error(tt.message, tt.code, tt.err)
			if got := e.Error(); got != tt.want {
				t.Errorf("httpError.Error() = %v, want %v", got, tt.want)
			}
		})
	}
}
