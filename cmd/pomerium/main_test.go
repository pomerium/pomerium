package main

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/pomerium/pomerium/internal/policy"

	"github.com/pomerium/pomerium/internal/config"
	"github.com/pomerium/pomerium/internal/middleware"
	"google.golang.org/grpc"
)

func Test_startRedirectServer(t *testing.T) {

	tests := []struct {
		name    string
		addr    string
		want    string
		wantErr bool
	}{
		{"empty", "", "", true},
		{":http", ":http", ":http", false},
		{"localhost:80", "localhost:80", "localhost:80", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := startRedirectServer(tt.addr)
			if (err != nil) != tt.wantErr {
				t.Errorf("startRedirectServer() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != nil {
				defer got.Close()
				ts := httptest.NewServer(got.Handler)
				defer ts.Close()
				_, err := http.Get(ts.URL)
				if !strings.Contains(err.Error(), "https") {
					t.Errorf("startRedirectServer() = %v, want %v", err, tt.want)
					return
				}
			}
		})
	}
}

func Test_newAuthenticateService(t *testing.T) {
	grpcAuth := middleware.NewSharedSecretCred("test")
	grpcOpts := []grpc.ServerOption{grpc.UnaryInterceptor(grpcAuth.ValidateRequest)}
	grpcServer := grpc.NewServer(grpcOpts...)
	mux := http.NewServeMux()

	tests := []struct {
		name  string
		s     string
		Field string
		Value string

		wantHostname string
		wantErr      bool
	}{
		{"wrong service", "proxy", "", "", "", false},
		{"bad", "authenticate", "SharedKey", "error!", "", true},
		{"good", "authenticate", "ClientID", "test", "auth.server.com", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authURL, _ := url.Parse("http://auth.server.com")
			testOpts := config.NewOptions()
			testOpts.Provider = "google"
			testOpts.ClientSecret = "TEST"
			testOpts.SharedKey = "YixWi1MYh77NMECGGIJQevoonYtVF+ZPRkQZrrmeRqM="
			testOpts.CookieSecret = "YixWi1MYh77NMECGGIJQevoonYtVF+ZPRkQZrrmeRqM="
			testOpts.AuthenticateURL = authURL
			testOpts.Services = tt.s

			if tt.Field != "" {
				testOptsField := reflect.ValueOf(testOpts).Elem().FieldByName(tt.Field)
				testOptsField.Set(reflect.ValueOf(tt).FieldByName("Value"))
			}

			_, err := newAuthenticateService(testOpts, mux, grpcServer)
			if (err != nil) != tt.wantErr {
				t.Errorf("newAuthenticateService() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

		})
	}
}

func Test_newAuthorizeService(t *testing.T) {
	os.Clearenv()
	grpcAuth := middleware.NewSharedSecretCred("test")
	grpcOpts := []grpc.ServerOption{grpc.UnaryInterceptor(grpcAuth.ValidateRequest)}
	grpcServer := grpc.NewServer(grpcOpts...)

	tests := []struct {
		name  string
		s     string
		Field string
		Value string

		wantErr bool
	}{
		{"wrong service", "proxy", "", "", false},
		{"bad option parsing", "authorize", "SharedKey", "false", true},
		{"good", "authorize", "SharedKey", "YixWi1MYh77NMECGGIJQevoonYtVF+ZPRkQZrrmeRqM=", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testOpts := config.NewOptions()
			testOpts.Services = tt.s
			testOpts.CookieSecret = "YixWi1MYh77NMECGGIJQevoonYtVF+ZPRkQZrrmeRqM="
			testPolicy := policy.Policy{From: "pomerium.io", To: "httpbin.org"}
			testPolicy.Validate()
			testOpts.Policies = []policy.Policy{
				testPolicy,
			}

			if tt.Field != "" {
				testOptsField := reflect.ValueOf(testOpts).Elem().FieldByName(tt.Field)
				testOptsField.Set(reflect.ValueOf(tt).FieldByName("Value"))
			}

			_, err := newAuthorizeService(testOpts, grpcServer)
			if (err != nil) != tt.wantErr {
				t.Errorf("newAuthorizeService() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func Test_newProxyeService(t *testing.T) {
	os.Clearenv()
	tests := []struct {
		name  string
		s     string
		Field string
		Value string

		wantErr bool
	}{
		{"wrong service", "authenticate", "", "", false},
		{"bad option parsing", "proxy", "SharedKey", "false", true},
		{"good", "proxy", "SharedKey", "YixWi1MYh77NMECGGIJQevoonYtVF+ZPRkQZrrmeRqM=", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mux := http.NewServeMux()
			testOpts := config.NewOptions()
			testPolicy := policy.Policy{From: "pomerium.io", To: "httpbin.org"}
			testPolicy.Validate()
			testOpts.Policies = []policy.Policy{
				testPolicy,
			}
			testOpts.AuthenticateURL, _ = url.Parse("https://authenticate.example.com")
			testOpts.AuthorizeURL, _ = url.Parse("https://authorize.example.com")
			testOpts.CookieSecret = "YixWi1MYh77NMECGGIJQevoonYtVF+ZPRkQZrrmeRqM="
			testOpts.Services = tt.s

			if tt.Field != "" {
				testOptsField := reflect.ValueOf(testOpts).Elem().FieldByName(tt.Field)
				testOptsField.Set(reflect.ValueOf(tt).FieldByName("Value"))
			}
			_, err := newProxyService(testOpts, mux)
			if (err != nil) != tt.wantErr {
				t.Errorf("newProxyService() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func Test_wrapMiddleware(t *testing.T) {
	o := &config.Options{
		Services: "all",
		Headers: map[string]string{
			"X-Content-Type-Options":    "nosniff",
			"X-Frame-Options":           "SAMEORIGIN",
			"X-XSS-Protection":          "1; mode=block",
			"Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
			"Content-Security-Policy":   "default-src 'none'; style-src 'self' 'sha256-pSTVzZsFAqd2U3QYu+BoBDtuJWaPM/+qMy/dBRrhb5Y='; img-src 'self';",
			"Referrer-Policy":           "Same-origin",
		}}
	mux := http.NewServeMux()
	req := httptest.NewRequest(http.MethodGet, "/404", nil)
	rr := httptest.NewRecorder()
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `OK`)
	})

	mux.Handle("/404", h)
	out := wrapMiddleware(o, mux)
	out.ServeHTTP(rr, req)
	expected := fmt.Sprintf("OK")
	body := rr.Body.String()

	if body != expected {
		t.Errorf("handler returned unexpected body: got %v want %v", body, expected)
	}
}
func Test_parseOptions(t *testing.T) {
	tests := []struct {
		name     string
		envKey   string
		envValue string

		wantSharedKey string
		wantErr       bool
	}{
		{"no shared secret", "", "", "", true},
		{"good", "SHARED_SECRET", "YixWi1MYh77NMECGGIJQevoonYtVF+ZPRkQZrrmeRqM=", "YixWi1MYh77NMECGGIJQevoonYtVF+ZPRkQZrrmeRqM=", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Setenv(tt.envKey, tt.envValue)
			defer os.Unsetenv(tt.envKey)

			got, err := parseOptions("")
			if (err != nil) != tt.wantErr {
				t.Errorf("parseOptions() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != nil && got.SharedKey != tt.wantSharedKey {
				t.Errorf("parseOptions()\n")
				t.Errorf("got: %+v\n", got.SharedKey)
				t.Errorf("want: %+v\n", tt.wantSharedKey)

			}
		})
	}
}

type mockService struct {
	fail    bool
	Updated bool
}

func (m *mockService) UpdateOptions(o *config.Options) error {

	m.Updated = true
	if m.fail {
		return fmt.Errorf("Failed")
	}
	return nil
}

func Test_handleConfigUpdate(t *testing.T) {
	os.Clearenv()
	os.Setenv("SHARED_SECRET", "foo")
	defer os.Unsetenv("SHARED_SECRET")

	blankOpts := config.NewOptions()
	goodOpts, _ := config.OptionsFromViper("")
	tests := []struct {
		name       string
		service    *mockService
		oldOpts    *config.Options
		wantUpdate bool
	}{
		{"good", &mockService{fail: false}, blankOpts, true},
		{"bad", &mockService{fail: true}, blankOpts, true},
		{"no change", &mockService{fail: false}, goodOpts, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handleConfigUpdate(tt.oldOpts, []config.OptionsUpdater{tt.service})
			if tt.service.Updated != tt.wantUpdate {
				t.Errorf("Failed to update config on service")
			}
		})
	}
}
