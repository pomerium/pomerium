package httputil

import (
	"math"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/go-cmp/cmp"
)

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

func TestRenderJSON(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		code     int
		v        any
		wantBody string
		wantCode int
	}{
		{
			"simple",
			http.StatusTeapot,
			struct {
				A string
				B string
				C int
			}{
				A: "A",
				B: "B",
				C: 1,
			},
			"{\"A\":\"A\",\"B\":\"B\",\"C\":1}\n",
			http.StatusTeapot,
		},
		{
			"map",
			http.StatusOK,
			map[string]any{
				"C": 1, // notice order does not matter
				"A": "A",
				"B": "B",
			},
			// alphabetical
			"{\"A\":\"A\",\"B\":\"B\",\"C\":1}\n", http.StatusOK,
		},
		{
			"bad!",
			http.StatusOK,
			map[string]any{
				"BAD BOI": math.Inf(1),
			},
			`{"error":"json: unsupported value: +Inf"}`, http.StatusInternalServerError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()

			RenderJSON(w, tt.code, tt.v)
			if diff := cmp.Diff(tt.wantBody, w.Body.String()); diff != "" {
				t.Errorf("TestRenderJSON:\n %s", diff)
			}
			if diff := cmp.Diff(tt.wantCode, w.Result().StatusCode); diff != "" {
				t.Errorf("TestRenderJSON:\n %s", diff)
			}
		})
	}
}
