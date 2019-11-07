package middleware // import "github.com/pomerium/pomerium/internal/middleware"

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/pomerium/pomerium/internal/cryptutil"
)

func hmacHelperFunc(rawRedirect string, timestamp time.Time, secret string) []byte {
	data := []byte(fmt.Sprint(rawRedirect, timestamp.Unix()))
	return cryptutil.GenerateHMAC(data, secret)
}

func Test_ValidSignature(t *testing.T) {
	t.Parallel()
	goodURL := "https://example.com/redirect"
	secretA := "41aOD7VNtQ1/KZDCGrkYpaHwB50JC1y6BDs2KPRVd2A="
	now := fmt.Sprint(time.Now().Unix())
	rawSig := hmacHelperFunc(goodURL, time.Now(), secretA)
	sig := base64.URLEncoding.EncodeToString(rawSig)
	staleTime := fmt.Sprint(time.Now().Add(-6 * time.Minute).Unix())

	tests := []struct {
		name        string
		redirectURI string
		sigVal      string
		timestamp   string
		secret      string
		want        bool
	}{
		{"good signature", goodURL, sig, now, secretA, true},
		{"empty redirect url", "", sig, now, secretA, false},
		{"bad redirect url", "https://google.com^", sig, now, secretA, false},
		{"malformed signature", goodURL, sig + "^", now, "&*&@**($&#(", false},
		{"malformed timestamp", goodURL, sig, now + "^", secretA, false},
		{"stale timestamp", goodURL, sig, staleTime, secretA, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ValidSignature(tt.redirectURI, tt.sigVal, tt.timestamp, tt.secret); got != tt.want {
				t.Errorf("ValidSignature() = %v, want %v", got, tt.want)
			}
		})
	}
}

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
			testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	secretA := "41aOD7VNtQ1/KZDCGrkYpaHwB50JC1y6BDs2KPRVd2A="
	now := fmt.Sprint(time.Now().Unix())
	goodURL := "https://example.com/redirect"
	rawSig := hmacHelperFunc(goodURL, time.Now(), secretA)
	sig := base64.URLEncoding.EncodeToString(rawSig)
	staleTime := fmt.Sprint(time.Now().Add(-6 * time.Minute).Unix())

	tests := []struct {
		name         string
		sharedSecret string
		redirectURI  string
		sig          string
		ts           string
		status       int
	}{
		{"valid signature", secretA, goodURL, sig, now, http.StatusOK},
		{"stale signature", secretA, goodURL, sig, staleTime, http.StatusBadRequest},
		{"malformed", secretA, goodURL, "%zzzzz", now, http.StatusBadRequest},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := url.Values{}
			v.Set("redirect_uri", tt.redirectURI)
			v.Set("ts", tt.ts)
			v.Set("sig", tt.sig)

			req := &http.Request{
				Method: http.MethodGet,
				URL:    &url.URL{RawQuery: v.Encode()}}
			if tt.name == "malformed" {
				req.URL.RawQuery = "sig=%zzzzz"
			}

			testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte("Hi"))
			})
			rr := httptest.NewRecorder()
			handler := ValidateSignature(tt.sharedSecret)(testHandler)
			handler.ServeHTTP(rr, req)
			if rr.Code != tt.status {
				t.Errorf("Status code differs. got %d want %d", rr.Code, tt.status)
				t.Errorf("%s", rr.Body)
			}
		})
	}
}

func TestHealthCheck(t *testing.T) {
	t.Parallel()
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hi"))
	})
	tests := []struct {
		name       string
		method     string
		clientPath string
		serverPath string

		wantStatus int
	}{
		{"good - Get", http.MethodGet, "/ping", "/ping", http.StatusOK},
		{"good - Head", http.MethodHead, "/ping", "/ping", http.StatusOK},
		{"bad - Options", http.MethodOptions, "/ping", "/ping", http.StatusMethodNotAllowed},
		{"bad - Put", http.MethodPut, "/ping", "/ping", http.StatusMethodNotAllowed},
		{"bad - Post", http.MethodPost, "/ping", "/ping", http.StatusMethodNotAllowed},
		{"bad - route miss", http.MethodGet, "/not-ping", "/ping", http.StatusOK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			r := httptest.NewRequest(tt.method, tt.clientPath, nil)
			w := httptest.NewRecorder()

			handler := Healthcheck(tt.serverPath, string("OK"))(testHandler)
			handler.ServeHTTP(w, r)
			if w.Code != tt.wantStatus {
				t.Errorf("code differs. got %d want %d body: %s", w.Code, tt.wantStatus, w.Body.String())
			}
		})
	}
}

func TestStripCookie(t *testing.T) {
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

			http.SetCookie(rr, &http.Cookie{
				Name:  tt.pomeriumCookie + "_csrf",
				Value: "pomerium csrf cookie!",
			})
			req := &http.Request{Header: http.Header{"Cookie": rr.Header()["Set-Cookie"]}}

			handler := StripCookie(tt.pomeriumCookie)(testHandler)
			handler.ServeHTTP(rr, req)

		})
	}
}

func TestTimeoutHandlerFunc(t *testing.T) {
	t.Parallel()
	fn := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		fmt.Fprint(w, http.StatusText(http.StatusOK))
		w.WriteHeader(http.StatusOK)
	})

	tests := []struct {
		name         string
		timeout      time.Duration
		timeoutError string
		wantStatus   int
		wantBody     string
	}{
		{"good", 1 * time.Second, "good timed out!?", http.StatusOK, http.StatusText(http.StatusOK)},
		{"timeout!", 1 * time.Nanosecond, "ruh roh", http.StatusServiceUnavailable, "ruh roh"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			w := httptest.NewRecorder()
			got := TimeoutHandlerFunc(tt.timeout, tt.timeoutError)(fn)
			got.ServeHTTP(w, r)
			if status := w.Code; status != tt.wantStatus {
				t.Errorf("SignRequest() error = %v, wantErr %v\n%v", w.Result().StatusCode, tt.wantStatus, w.Body.String())
			}
			if body := w.Body.String(); tt.wantBody != body {
				t.Errorf("SignRequest() body = %v, want %v", body, tt.wantBody)
			}
		})
	}
}
