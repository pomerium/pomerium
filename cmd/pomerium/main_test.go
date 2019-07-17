package main

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"testing"

	"github.com/pomerium/pomerium/internal/config"
	"github.com/pomerium/pomerium/internal/middleware"
	"google.golang.org/grpc"
)

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
			testOpts, err := config.NewOptions("https://authenticate.example", "https://authorize.example")
			if err != nil {
				t.Fatal(err)
			}
			testOpts.Provider = "google"
			testOpts.ClientSecret = "TEST"
			testOpts.SharedKey = "YixWi1MYh77NMECGGIJQevoonYtVF+ZPRkQZrrmeRqM="
			testOpts.CookieSecret = "YixWi1MYh77NMECGGIJQevoonYtVF+ZPRkQZrrmeRqM="
			testOpts.Services = tt.s

			if tt.Field != "" {
				testOptsField := reflect.ValueOf(testOpts).Elem().FieldByName(tt.Field)
				testOptsField.Set(reflect.ValueOf(tt).FieldByName("Value"))
			}

			_, err = newAuthenticateService(*testOpts, mux, grpcServer)
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
			testOpts, err := config.NewOptions("https://some.example", "https://some.example")
			if err != nil {
				t.Fatal(err)
			}
			testOpts.Services = tt.s
			testOpts.CookieSecret = "YixWi1MYh77NMECGGIJQevoonYtVF+ZPRkQZrrmeRqM="
			testPolicy := config.Policy{From: "http://some.example", To: "https://some.example"}
			if err := testPolicy.Validate(); err != nil {
				t.Fatal(err)
			}
			testOpts.Policies = []config.Policy{
				testPolicy,
			}

			if tt.Field != "" {
				testOptsField := reflect.ValueOf(testOpts).Elem().FieldByName(tt.Field)
				testOptsField.Set(reflect.ValueOf(tt).FieldByName("Value"))
			}

			_, err = newAuthorizeService(*testOpts, grpcServer)
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
			testOpts, err := config.NewOptions("https://authenticate.example", "https://authorize.example")
			if err != nil {
				t.Fatal(err)
			}
			testPolicy := config.Policy{From: "http://some.example", To: "http://some.example"}
			if err := testPolicy.Validate(); err != nil {
				t.Fatal(err)
			}
			testOpts.Policies = []config.Policy{
				testPolicy,
			}

			AuthenticateURL, _ := url.Parse("https://authenticate.example.com")
			AuthorizeURL, _ := url.Parse("https://authorize.example.com")

			testOpts.AuthenticateURL = AuthenticateURL
			testOpts.AuthorizeURL = AuthorizeURL
			testOpts.CookieSecret = "YixWi1MYh77NMECGGIJQevoonYtVF+ZPRkQZrrmeRqM="
			testOpts.Services = tt.s

			if tt.Field != "" {
				testOptsField := reflect.ValueOf(testOpts).Elem().FieldByName(tt.Field)
				testOptsField.Set(reflect.ValueOf(tt).FieldByName("Value"))
			}
			_, err = newProxyService(*testOpts, mux)
			if (err != nil) != tt.wantErr {
				t.Errorf("newProxyService() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func Test_mainHandler(t *testing.T) {
	o := config.Options{
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
	out := mainHandler(&o, mux)
	out.ServeHTTP(rr, req)
	expected := fmt.Sprintf("OK")
	body := rr.Body.String()

	if body != expected {
		t.Errorf("handler returned unexpected body: got %v want %v", body, expected)
	}
}
