package middleware

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/pomerium/pomerium/internal/urlutil"
)

func TestSetHeaders(t *testing.T) {
	tests := []struct {
		name            string
		securityHeaders map[string]string
	}{
		{"one option", map[string]string{"X-Frame-Options": "DENY"}},
		{"two options", map[string]string{"X-Frame-Options": "DENY", "A": "B"}},
	}
	req, err := http.NewRequest(http.MethodGet, "/", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				for k, want := range tt.securityHeaders {
					if got := w.Header().Get(k); want != got {
						t.Errorf("want %s got %q", want, got)
					}
				}
			})
			rr := httptest.NewRecorder()
			handler := SetHeaders(tt.securityHeaders)(testHandler)
			handler.ServeHTTP(rr, req)
		})
	}
}

func TestValidateSignature(t *testing.T) {
	t.Parallel()
	fn := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, http.StatusText(http.StatusOK))
		w.WriteHeader(http.StatusOK)
	})

	tests := []struct {
		name       string
		secretA    []byte
		secretB    []byte
		wantStatus int
		wantBody   string
	}{
		{"good", []byte("secret"), []byte("secret"), http.StatusOK, http.StatusText(http.StatusOK)},
		{"secret mistmatch", []byte("secret"), []byte("hunter42"), http.StatusBadRequest, "{\"Status\":400}\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signedURL := urlutil.NewSignedURL(tt.secretB, &url.URL{Scheme: "https", Host: "pomerium.io"})

			r := httptest.NewRequest(http.MethodGet, signedURL.String(), nil)
			r.Header.Set("Accept", "application/json")
			w := httptest.NewRecorder()
			got := ValidateSignature(tt.secretA)(fn)
			got.ServeHTTP(w, r)
			if status := w.Code; status != tt.wantStatus {
				t.Errorf("ValidateSignature() error = %v, wantErr %v\n%v", w.Result().StatusCode, tt.wantStatus, w.Body.String())
			}
			body := w.Body.String()
			if diff := cmp.Diff(body, tt.wantBody); diff != "" {
				t.Errorf("ValidateSignature() %s", diff)
				t.Errorf("%s", signedURL)
			}
		})
	}
}

func TestRequireBasicAuth(t *testing.T) {
	t.Parallel()

	fn := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, http.StatusText(http.StatusOK))
		w.WriteHeader(http.StatusOK)
	})

	tests := []struct {
		name       string
		givenUser  string
		givenPass  string
		wantUser   string
		wantPass   string
		wantStatus int
	}{
		{"good", "foo", "bar", "foo", "bar", 200},
		{"bad pass", "foo", "bar", "foo", "buzz", 401},
		{"bad user", "foo", "bar", "buzz", "bar", 401},
		{"empty", "", "", "", "", 401}, // don't add auth
		{"empty user", "", "bar", "", "bar", 200},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, "/", nil)
			if err != nil {
				t.Fatal(err)
			}
			if tt.givenUser != "" || tt.givenPass != "" {
				req.SetBasicAuth(tt.givenUser, tt.givenPass)
			}

			rr := httptest.NewRecorder()
			handler := RequireBasicAuth(tt.wantUser, tt.wantPass)(fn)
			handler.ServeHTTP(rr, req)
			if status := rr.Code; status != tt.wantStatus {
				t.Errorf("RequireBasicAuth() error = %v, wantErr %v\n%v", rr.Result().StatusCode, tt.wantStatus, rr.Body.String())
			}
		})
	}
}
