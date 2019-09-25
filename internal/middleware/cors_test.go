package middleware // import "github.com/pomerium/pomerium/internal/middleware"

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func someOtherMiddleware(s string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Some-Other-Middleware", s)
			next.ServeHTTP(w, r)
		})
	}
}
func TestCorsBypass(t *testing.T) {
	t.Parallel()
	fn := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		fmt.Fprint(w, http.StatusText(http.StatusOK))
		w.WriteHeader(http.StatusOK)
	})

	tests := []struct {
		name       string
		method     string
		header     http.Header
		wantStatus int
		wantHeader string
	}{
		{"good", http.MethodOptions, http.Header{"Access-Control-Request-Method": []string{"GET"}, "Origin": []string{"localhost"}}, 200, ""},
		{"invalid cors - non options request", http.MethodGet, http.Header{"Access-Control-Request-Method": []string{"GET"}, "Origin": []string{"localhost"}}, 200, "BAD"},
		{"invalid cors - Origin not set", http.MethodOptions, http.Header{"Access-Control-Request-Method": []string{"GET"}, "Origin": []string{""}}, 200, "BAD"},
		{"invalid cors - Access-Control-Request-Method not set", http.MethodOptions, http.Header{"Access-Control-Request-Method": []string{""}, "Origin": []string{"*"}}, 200, "BAD"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &http.Request{
				Method: tt.method,
				Header: tt.header,
			}
			w := httptest.NewRecorder()
			target := fn
			got := CorsBypass(target)(someOtherMiddleware("BAD")(target))
			got.ServeHTTP(w, r)
			if status := w.Code; status != tt.wantStatus {
				t.Errorf("TestCorsBypass() error = %v, wantErr %v\n%v", w.Result().StatusCode, tt.wantStatus, w.Body.String())
			}
			if header := w.Header().Get("Some-Other-Middleware"); tt.wantHeader != header {
				t.Errorf("TestCorsBypass() header = %v, want %v", header, tt.wantHeader)
			}
		})
	}
}
