package httputil // import "github.com/pomerium/pomerium/internal/httputil"

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestCSRFFailureHandler(t *testing.T) {

	tests := []struct {
		name string

		wantBody   string
		wantStatus int
	}{
		{"basic csrf failure", "{\"error\":\"CSRF Failure\"}\n", http.StatusForbidden},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.Header.Set("Accept", "application/json")
			w := httptest.NewRecorder()
			CSRFFailureHandler(w, r)
			gotBody := w.Body.String()
			gotStatus := w.Result().StatusCode
			if diff := cmp.Diff(gotBody, tt.wantBody); diff != "" {
				t.Errorf("RetrieveSession() = %s", diff)
			}
			if diff := cmp.Diff(gotStatus, tt.wantStatus); diff != "" {
				t.Errorf("RetrieveSession() = %s", diff)
			}
		})
	}
}
