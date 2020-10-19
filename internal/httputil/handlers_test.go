package httputil

import (
	"errors"
	"math"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/go-cmp/cmp"
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

func TestHandlerFunc_ServeHTTP(t *testing.T) {

	tests := []struct {
		name     string
		f        HandlerFunc
		wantBody string
	}{
		{"good http error", func(w http.ResponseWriter, r *http.Request) error { return NewError(404, errors.New("404")) }, "{\"Status\":404,\"Error\":\"Not Found: 404\"}\n"},
		{"good std error", func(w http.ResponseWriter, r *http.Request) error { return errors.New("404") }, "{\"Status\":500,\"Error\":\"Internal Server Error: 404\"}\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/", nil)
			r.Header.Set("Accept", "application/json")
			w := httptest.NewRecorder()
			tt.f.ServeHTTP(w, r)
			if diff := cmp.Diff(tt.wantBody, w.Body.String()); diff != "" {
				t.Errorf("ErrorResponse status:\n %s", diff)
			}
		})
	}
}

func TestRenderJSON(t *testing.T) {

	tests := []struct {
		name     string
		code     int
		v        interface{}
		wantBody string
	}{
		{"simple",
			http.StatusOK,
			struct {
				A string
				B string
				C int
			}{
				A: "A",
				B: "B",
				C: 1,
			},
			"{\"A\":\"A\",\"B\":\"B\",\"C\":1}\n"},
		{"map",
			http.StatusOK,
			map[string]interface{}{
				"C": 1, // notice order does not matter
				"A": "A",
				"B": "B",
			},
			// alphabetical
			"{\"A\":\"A\",\"B\":\"B\",\"C\":1}\n"},
		{"bad!",
			http.StatusOK,
			map[string]interface{}{
				"BAD BOI": math.Inf(1),
			},
			`{"error":"json: unsupported value: +Inf"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()

			RenderJSON(w, tt.code, tt.v)
			if diff := cmp.Diff(tt.wantBody, w.Body.String()); diff != "" {
				t.Errorf("TestRenderJSON:\n %s", diff)
			}
		})
	}
}
