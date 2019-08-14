package main

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/signal"
	"reflect"
	"syscall"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/pomerium/pomerium/internal/config"
	"github.com/pomerium/pomerium/internal/httputil"
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

func Test_configToServerOptions(t *testing.T) {
	tests := []struct {
		name string
		opt  *config.Options
		want *httputil.ServerOptions
	}{
		{"simple convert", &config.Options{Addr: ":80"}, &httputil.ServerOptions{Addr: ":80"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if diff := cmp.Diff(configToServerOptions(tt.opt), tt.want); diff != "" {
				t.Errorf("configToServerOptions() = \n %s", diff)
			}
		})
	}
}

func Test_setupGRPCServer(t *testing.T) {
	tests := []struct {
		name     string
		opt      *config.Options
		dontWant *grpc.Server
	}{
		{"good", &config.Options{SharedKey: "test"}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if diff := cmp.Diff(setupGRPCServer(tt.opt), tt.dontWant); diff == "" {
				t.Errorf("setupGRPCServer() = \n %s", diff)
			}
		})
	}
}

func Test_setupTracing(t *testing.T) {
	tests := []struct {
		name string
		opt  *config.Options
	}{
		{"good jaeger", &config.Options{TracingProvider: "jaeger", TracingJaegerAgentEndpoint: "localhost:0", TracingJaegerCollectorEndpoint: "localhost:0"}},
		{"dont register aything", &config.Options{}},
		{"bad provider", &config.Options{TracingProvider: "bad provider"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setupTracing(tt.opt)
		})
	}
}

func Test_setupMetrics(t *testing.T) {
	tests := []struct {
		name string
		opt  *config.Options
	}{
		{"dont register aything", &config.Options{}},
		{"good metrics server", &config.Options{MetricsAddr: "localhost:0"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := make(chan os.Signal, 1)
			signal.Notify(c, syscall.SIGINT)
			defer signal.Stop(c)
			setupMetrics(tt.opt)
			syscall.Kill(syscall.Getpid(), syscall.SIGINT)
			waitSig(t, c, syscall.SIGINT)

		})
	}
}

func Test_setupHTTPRedirectServer(t *testing.T) {
	tests := []struct {
		name string
		opt  *config.Options
	}{
		{"dont register aything", &config.Options{}},
		{"good redirect server", &config.Options{HTTPRedirectAddr: "localhost:0"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := make(chan os.Signal, 1)
			signal.Notify(c, syscall.SIGINT)
			defer signal.Stop(c)
			setupHTTPRedirectServer(tt.opt)
			syscall.Kill(syscall.Getpid(), syscall.SIGINT)
			waitSig(t, c, syscall.SIGINT)

		})
	}
}

func waitSig(t *testing.T, c <-chan os.Signal, sig os.Signal) {
	select {
	case s := <-c:
		if s != sig {
			t.Fatalf("signal was %v, want %v", s, sig)
		}
	case <-time.After(1 * time.Second):
		t.Fatalf("timeout waiting for %v", sig)
	}
}
