package middleware

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func Test_SameSubdomain(t *testing.T) {

	tests := []struct {
		name        string
		uri         string
		rootDomains string
		want        bool
	}{
		{"good url redirect", "https://example.com/redirect", "https://example.com", true},
		{"simple sub", "https://auth.example.com", "https://test.example.com", true},
		{"mismatched lengths", "https://auth.auth.example.com", "https://test.example.com", false},
		{"bad domain", "https://auth.example.com/redirect", "https://test.notexample.com", false},
		{"malformed url", "^example.com/redirect", "https://notexample.com", false},
		{"empty domain list", "https://example.com/redirect", ".com", false},
		{"empty domain", "https://example.com/redirect", "", false},
		{"empty url", "", "example.com", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, _ := url.Parse(tt.uri)
			j, _ := url.Parse(tt.rootDomains)
			if got := SameSubdomain(u, j); got != tt.want {
				t.Errorf("SameSubdomain() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_ValidSignature(t *testing.T) {
	goodURL := "https://example.com/redirect"
	secretA := "41aOD7VNtQ1/KZDCGrkYpaHwB50JC1y6BDs2KPRVd2A="
	now := fmt.Sprint(time.Now().Unix())
	rawSig := redirectURLSignature(goodURL, time.Now(), secretA)
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
		{"good signature", goodURL, string(sig), now, secretA, true},
		{"empty redirect url", "", string(sig), now, secretA, false},
		{"bad redirect url", "https://google.com^", string(sig), now, secretA, false},
		{"malformed signature", goodURL, string(sig + "^"), now, "&*&@**($&#(", false},
		{"malformed timestamp", goodURL, string(sig), now + "^", secretA, false},
		{"stale timestamp", goodURL, string(sig), staleTime, secretA, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ValidSignature(tt.redirectURI, tt.sigVal, tt.timestamp, tt.secret); got != tt.want {
				t.Errorf("ValidSignature() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_redirectURLSignature(t *testing.T) {
	tests := []struct {
		name        string
		rawRedirect string
		timestamp   time.Time
		secret      string
		want        string
	}{
		{"good signature", "https://example.com/redirect", time.Unix(1546797901, 0), "K3yqsJPahIzu5CdfCVJlIK4N8Dc135-27Tg1ROuQdhc=", "XeVJC2Iysq7mRUwOL3FX_5vx1d_kZV2HONHNig9fcKk="},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := redirectURLSignature(tt.rawRedirect, tt.timestamp, tt.secret)
			out := base64.URLEncoding.EncodeToString(got)
			if out != tt.want {
				t.Errorf("redirectURLSignature() = %v, want %v", tt.want, out)
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

func TestValidateRedirectURI(t *testing.T) {
	tests := []struct {
		name        string
		rootDomain  string
		redirectURI string
		status      int
	}{
		{"simple", "https://auth.google.com", "https://b.google.com", http.StatusOK},
		{"deep ok", "https://a.some.really.deep.sub.domain.google.com", "https://b.some.really.deep.sub.domain.google.com", http.StatusOK},
		{"bad match", "https://auth.aol.com", "https://test.google.com", http.StatusBadRequest},
		{"bad simple", "https://auth.corp.aol.com", "https://test.corp.google.com", http.StatusBadRequest},
		{"deep bad", "https://a.some.really.deep.sub.domain.scroogle.com", "https://b.some.really.deep.sub.domain.google.com", http.StatusBadRequest},
		{"with cname", "https://auth.google.com", "https://www.google.com", http.StatusOK},
		{"with path", "https://auth.google.com", "https://www.google.com/path", http.StatusOK},
		{"http mistmatch", "https://auth.google.com", "http://www.google.com/path", http.StatusOK},
		{"http", "http://auth.google.com", "http://www.google.com/path", http.StatusOK},
		{"ip", "http://1.1.1.1", "http://8.8.8.8", http.StatusBadRequest},
		{"malformed, invalid hex digits", "https://auth.google.com", "%zzzzz", http.StatusBadRequest},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &http.Request{
				Method: http.MethodGet,
				URL:    &url.URL{RawQuery: fmt.Sprintf("redirect_uri=%s", tt.redirectURI)},
			}
			testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte("Hi"))
			})
			rr := httptest.NewRecorder()
			u, _ := url.Parse(tt.rootDomain)
			handler := ValidateRedirectURI(u)(testHandler)
			handler.ServeHTTP(rr, req)
			if rr.Code != tt.status {
				t.Errorf("Status code differs. got %d want %d", rr.Code, tt.status)
				t.Errorf("%s", rr.Body)
			}
		})
	}
}

func TestValidateClientSecret(t *testing.T) {
	tests := []struct {
		name              string
		sharedSecret      string
		clientGetValue    string
		clientHeaderValue string
		status            int
	}{
		{"simple", "secret", "secret", "secret", http.StatusOK},
		{"missing get param, valid header", "secret", "", "secret", http.StatusOK},
		{"missing both", "secret", "", "", http.StatusUnauthorized},
		{"simple bad", "bad-secret", "secret", "", http.StatusUnauthorized},
		{"malformed, invalid hex digits", "secret", "%zzzzz", "", http.StatusBadRequest},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &http.Request{
				Method: http.MethodGet,
				Header: http.Header{"X-Client-Secret": []string{tt.clientHeaderValue}},
				URL:    &url.URL{RawQuery: fmt.Sprintf("shared_secret=%s", tt.clientGetValue)},
			}
			testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte("Hi"))
			})
			rr := httptest.NewRecorder()
			handler := ValidateClientSecret(tt.sharedSecret)(testHandler)
			handler.ServeHTTP(rr, req)
			if rr.Code != tt.status {
				t.Errorf("Status code differs. got %d want %d", rr.Code, tt.status)
				t.Errorf("%s", rr.Body)
			}
		})
	}
}

func TestValidateSignature(t *testing.T) {
	secretA := "41aOD7VNtQ1/KZDCGrkYpaHwB50JC1y6BDs2KPRVd2A="
	now := fmt.Sprint(time.Now().Unix())
	goodURL := "https://example.com/redirect"
	rawSig := redirectURLSignature(goodURL, time.Now(), secretA)
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
		{"stale signature", secretA, goodURL, sig, staleTime, http.StatusUnauthorized},
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
	tests := []struct {
		name       string
		method     string
		clientPath string
		expected   []byte
	}{
		{"good", http.MethodGet, "/ping", []byte("OK")},
		//tood(bdd): miss?
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			req, err := http.NewRequest(http.MethodGet, tt.clientPath, nil)
			if err != nil {
				t.Fatal(err)
			}

			testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte("Hi"))
			})
			rr := httptest.NewRecorder()
			handler := Healthcheck(tt.clientPath, string(tt.expected))(testHandler)
			handler.ServeHTTP(rr, req)
			if rr.Body.String() != string(tt.expected) {
				t.Errorf("body differs. got %ss want %ss", rr.Body, tt.expected)
				t.Errorf("%s", rr.Body)
			}
		})
	}
}

// Redirect to a fixed URL
type handlerHelper struct {
	msg string
}

func (rh *handlerHelper) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(rh.msg))
}

func handlerHelp(msg string) http.Handler {
	return &handlerHelper{msg}
}
func TestValidateHost(t *testing.T) {
	m := make(map[string]http.Handler)
	m["google.com"] = handlerHelp("google")

	tests := []struct {
		name       string
		validHosts map[string]http.Handler
		clientPath string
		expected   []byte
		status     int
	}{
		{"good", m, "google.com", []byte("google"), 200},
		{"no route", m, "googles.com", []byte("google"), 404},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, tt.clientPath, nil)
			if err != nil {
				t.Fatal(err)
			}
			rr := httptest.NewRecorder()

			var testHandler http.Handler
			if tt.validHosts[tt.clientPath] != nil {
				tt.validHosts[tt.clientPath].ServeHTTP(rr, req)
				testHandler = tt.validHosts[tt.clientPath]
			} else {
				testHandler = handlerHelp("ok")
			}
			handler := ValidateHost(tt.validHosts)(testHandler)
			handler.ServeHTTP(rr, req)

			if rr.Code != tt.status {
				t.Errorf("Status code differs. got %d want %d", rr.Code, tt.status)
				t.Errorf("%s", rr.Body)
			}

		})
	}
}
