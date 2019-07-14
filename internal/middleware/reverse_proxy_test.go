package middleware // import "github.com/pomerium/pomerium/internal/middleware"

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/pomerium/pomerium/internal/cryptutil"
)

const exampleKey = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIM3mpZIWXCX9yEgxU6s57CbtbUNDBSCEAtQF5fUWHpcQoAoGCCqGSM49
AwEHoUQDQgAEhPQv+LACPVNmBTK0xSTzbpEPkRrk1eUt1BOa32SEfUPzNi4IWeZ/
KKITt2q1IqpV2KMSbVDyr9ijv/Xh98iyEw==
-----END EC PRIVATE KEY-----
`

func TestSignRequest(t *testing.T) {
	tests := []struct {
		name string

		id     string
		email  string
		groups string
		header string
	}{
		{"good", "id", "email", "group", "Jwt"},
	}
	req, err := http.NewRequest(http.MethodGet, "/", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				r.Header.Set(fmt.Sprintf("%s-header", tt.id), tt.id)
				r.Header.Set(fmt.Sprintf("%s-header", tt.email), tt.email)
				r.Header.Set(fmt.Sprintf("%s-header", tt.groups), tt.groups)

			})
			rr := httptest.NewRecorder()
			signer, err := cryptutil.NewES256Signer([]byte(exampleKey), "audience")
			if err != nil {
				t.Fatal(err)
			}

			handler := SignRequest(signer, tt.id, tt.email, tt.groups, tt.header)(testHandler)
			handler.ServeHTTP(rr, req)
			jwt := req.Header["Jwt"]
			if len(jwt) != 1 {
				t.Errorf("no jwt found %v", req.Header)
			}
		})
	}
}

func TestStripPomeriumCookie(t *testing.T) {
	tests := []struct {
		name           string
		pomeriumCookie string
		otherCookies   []string
	}{
		{"good", "pomerium", []string{"x", "y", "z"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				for _, cookie := range r.Cookies() {
					if cookie.Name == tt.pomeriumCookie {
						t.Errorf("cookie not stripped %s", r.Cookies())
					}
				}
			})
			rr := httptest.NewRecorder()
			for _, cn := range tt.otherCookies {
				http.SetCookie(rr, &http.Cookie{
					Name:  cn,
					Value: "some other cookie",
				})
			}

			http.SetCookie(rr, &http.Cookie{
				Name:  tt.pomeriumCookie,
				Value: "pomerium cookie!",
			})
			req := &http.Request{Header: http.Header{"Cookie": rr.Header()["Set-Cookie"]}}

			handler := StripPomeriumCookie(tt.pomeriumCookie)(testHandler)
			handler.ServeHTTP(rr, req)

		})
	}
}
