package httputil

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHealthCheck(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		method string

		wantStatus int
	}{
		{"good - Get", http.MethodGet, http.StatusOK},
		{"good - Head", http.MethodHead, http.StatusOK},
		{"bad - Options", http.MethodOptions, http.StatusMethodNotAllowed},
		{"bad - Put", http.MethodPut, http.StatusMethodNotAllowed},
		{"bad - Post", http.MethodPost, http.StatusMethodNotAllowed},
		{"bad - route miss", http.MethodGet, http.StatusOK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			r := httptest.NewRequest(tt.method, "/", nil)
			w := httptest.NewRecorder()

			HealthCheck(w, r)
			if w.Code != tt.wantStatus {
				t.Errorf("code differs. got %d want %d body: %s", w.Code, tt.wantStatus, w.Body.String())
			}
		})
	}
}

func TestRedirect(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		method string

		url  string
		code int

		wantStatus int
	}{
		{"good", http.MethodGet, "https://pomerium.io", http.StatusFound, http.StatusFound},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			r := httptest.NewRequest(tt.method, "/", nil)
			w := httptest.NewRecorder()

			Redirect(w, r, tt.url, tt.code)
			if w.Code != tt.wantStatus {
				t.Errorf("code differs. got %d want %d body: %s", w.Code, tt.wantStatus, w.Body.String())
			}
			if w.Result().Header.Get(HeaderPomeriumResponse) == "" {
				t.Errorf("pomerium header not found")
			}
		})
	}
}
