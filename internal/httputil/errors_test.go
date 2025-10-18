package httputil

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestHTTPError_ErrorResponse(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		Status  int
		Err     error
		reqType string

		wantStatus int
		wantBody   string
	}{
		{"404 json", http.StatusNotFound, errors.New("route not known"), "application/json", http.StatusNotFound, "{\"Status\":404}\n"},
		{"404 html", http.StatusNotFound, errors.New("route not known"), "", http.StatusNotFound, ""},
		{"302 found", http.StatusFound, errors.New("redirect"), "", http.StatusFound, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fn := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				err := NewError(tt.Status, tt.Err)
				var e *HTTPError
				if errors.As(err, &e) {
					e.ErrorResponse(r.Context(), w, r)
				} else {
					http.Error(w, "coulnd't convert error type", http.StatusTeapot)
				}
			})
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.Header.Set("Accept", tt.reqType)
			w := httptest.NewRecorder()
			fn(w, r)
			if diff := cmp.Diff(tt.wantStatus, w.Code); diff != "" {
				t.Errorf("ErrorResponse status:\n %s", diff)
			}
			if tt.reqType == "application/json" {
				if diff := cmp.Diff(tt.wantBody, w.Body.String()); diff != "" {
					t.Errorf("ErrorResponse status:\n %s", diff)
				}
			}
		})
	}
}

func TestNewError(t *testing.T) {
	tests := []struct {
		name    string
		status  int
		err     error
		wantErr bool
	}{
		{"good", 404, errors.New("error"), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := NewError(tt.status, tt.err)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewError() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil && !errors.Is(err, tt.err) {
				t.Errorf("NewError() unwrap fail = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
