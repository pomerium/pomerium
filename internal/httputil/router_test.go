package httputil

import (
	"reflect"
	"testing"

	"github.com/gorilla/mux"
)

// func TestCSRFFailureHandler(t *testing.T) {

// 	tests := []struct {
// 		name string

// 		wantBody   string
// 		wantStatus int
// 	}{
// 		{"basic csrf failure", "{\"error\":\"CSRF Failure\"}\n", http.StatusForbidden},
// 	}
// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			r := httptest.NewRequest(http.MethodGet, "/", nil)
// 			r.Header.Set("Accept", "application/json")
// 			w := httptest.NewRecorder()
// 			HandlerFunc(CSRFFailureHandler).ServeHTTP(w, r)
// 			gotBody := w.Body.String()
// 			gotStatus := w.Result().StatusCode
// 			if diff := cmp.Diff(gotBody, tt.wantBody); diff != "" {
// 				t.Errorf("RetrieveSession() = %s", diff)
// 			}
// 			if diff := cmp.Diff(gotStatus, tt.wantStatus); diff != "" {
// 				t.Errorf("RetrieveSession() = %s", diff)
// 			}
// 		})
// 	}
// }

func TestNewRouter(t *testing.T) {
	tests := []struct {
		name string
		want *mux.Router
	}{
		{"this is a gorilla router right?", mux.NewRouter()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewRouter(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewRouter() = %v, want %v", got, tt.want)
			}
		})
	}
}
