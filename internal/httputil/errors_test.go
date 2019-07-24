package httputil

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestErrorResponse(t *testing.T) {
	tests := []struct {
		name string
		rw   http.ResponseWriter
		r    *http.Request
		e    *Error
	}{
		{"good", httptest.NewRecorder(), &http.Request{Method: http.MethodGet}, &Error{Code: http.StatusBadRequest, Message: "missing id token"}},
		{"good json", httptest.NewRecorder(), &http.Request{Method: http.MethodGet, Header: http.Header{"Accept": []string{"application/json"}}}, &Error{Code: http.StatusBadRequest, Message: "missing id token"}},
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
		CanDebug bool
		want     string
	}{
		{"good", "short and stout", http.StatusTeapot, false, "418 I'm a teapot: short and stout"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := Error{
				Message:  tt.Message,
				Code:     tt.Code,
				CanDebug: tt.CanDebug,
			}
			if got := h.Error(); got != tt.want {
				t.Errorf("Error.Error() = %v, want %v", got, tt.want)
			}
		})
	}
}
