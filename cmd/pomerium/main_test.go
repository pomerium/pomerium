package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"

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
	os.Clearenv()
	grpcAuth := middleware.NewSharedSecretCred("test")
	grpcOpts := []grpc.ServerOption{grpc.UnaryInterceptor(grpcAuth.ValidateRequest)}
	grpcServer := grpc.NewServer(grpcOpts...)
	mux := http.NewServeMux()

	tests := []struct {
		name     string
		s        string
		envKey   string
		envValue string

		wantHostname string
		wantErr      bool
	}{
		{"wrong service", "proxy", "", "", "", false},
		{"bad", "authenticate", "SHARED_SECRET", "error!", "", true},
		{"bad emv", "authenticate", "COOKIE_REFRESH", "error!", "", true},
		{"good", "authenticate", "IDP_CLIENT_ID", "test", "auth.server.com", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Setenv("IDP_PROVIDER", "google")
			os.Setenv("IDP_CLIENT_SECRET", "TEST")
			os.Setenv("SHARED_SECRET", "YixWi1MYh77NMECGGIJQevoonYtVF+ZPRkQZrrmeRqM=")
			os.Setenv("COOKIE_SECRET", "YixWi1MYh77NMECGGIJQevoonYtVF+ZPRkQZrrmeRqM=")
			os.Setenv("AUTHENTICATE_SERVICE_URL", "http://auth.server.com")
			defer os.Unsetenv("IDP_CLIENT_ID")
			defer os.Unsetenv("IDP_CLIENT_SECRET")
			defer os.Unsetenv("SHARED_SECRET")
			defer os.Unsetenv("COOKIE_SECRET")

			os.Setenv(tt.envKey, tt.envValue)
			defer os.Unsetenv(tt.envKey)

			_, err := newAuthenticateService(tt.s, mux, grpcServer)
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
		name     string
		s        string
		envKey   string
		envValue string

		wantErr bool
	}{
		{"wrong service", "proxy", "", "", false},
		{"bad option parsing", "authorize", "SHARED_SECRET", "false", true},
		{"bad env", "authorize", "POLICY", "error!", true},
		{"good", "authorize", "SHARED_SECRET", "YixWi1MYh77NMECGGIJQevoonYtVF+ZPRkQZrrmeRqM=", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Setenv("POLICY", "LSBmcm9tOiBodHRwYmluLmNvcnAuYmV5b25kcGVyaW1ldGVyLmNvbQogIHRvOiBodHRwOi8vaHR0cGJpbgogIGFsbG93ZWRfZG9tYWluczoKICAgIC0gcG9tZXJpdW0uaW8KICBjb3JzX2FsbG93X3ByZWZsaWdodDogdHJ1ZQogIHRpbWVvdXQ6IDMwcwotIGZyb206IGV4dGVybmFsLWh0dHBiaW4uY29ycC5iZXlvbmRwZXJpbWV0ZXIuY29tCiAgdG86IGh0dHBiaW4ub3JnCiAgYWxsb3dlZF9kb21haW5zOgogICAgLSBnbWFpbC5jb20KLSBmcm9tOiB3ZWlyZGx5c3NsLmNvcnAuYmV5b25kcGVyaW1ldGVyLmNvbQogIHRvOiBodHRwOi8vbmV2ZXJzc2wuY29tCiAgYWxsb3dlZF91c2VyczoKICAgIC0gYmRkQHBvbWVyaXVtLmlvCiAgYWxsb3dlZF9ncm91cHM6CiAgICAtIGFkbWlucwogICAgLSBkZXZlbG9wZXJzCi0gZnJvbTogaGVsbG8uY29ycC5iZXlvbmRwZXJpbWV0ZXIuY29tCiAgdG86IGh0dHA6Ly9oZWxsbzo4MDgwCiAgYWxsb3dlZF9ncm91cHM6CiAgICAtIGFkbWlucw==")
			os.Setenv("COOKIE_SECRET", "YixWi1MYh77NMECGGIJQevoonYtVF+ZPRkQZrrmeRqM=")
			defer os.Unsetenv("SHARED_SECRET")
			defer os.Unsetenv("COOKIE_SECRET")
			os.Setenv(tt.envKey, tt.envValue)
			defer os.Unsetenv(tt.envKey)
			_, err := newAuthorizeService(tt.s, grpcServer)
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
		name     string
		s        string
		envKey   string
		envValue string

		wantErr bool
	}{
		{"wrong service", "authenticate", "", "", false},
		{"bad option parsing", "proxy", "SHARED_SECRET", "false", true},
		{"bad env", "proxy", "POLICY", "error!", true},
		{"bad encoding for envar", "proxy", "COOKIE_REFRESH", "error!", true},
		{"good", "proxy", "SHARED_SECRET", "YixWi1MYh77NMECGGIJQevoonYtVF+ZPRkQZrrmeRqM=", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mux := http.NewServeMux()

			os.Setenv("AUTHENTICATE_SERVICE_URL", "https://authenticate.example.com")
			os.Setenv("AUTHORIZE_SERVICE_URL", "https://authorize.example.com")
			os.Setenv("POLICY", "LSBmcm9tOiBodHRwYmluLmNvcnAuYmV5b25kcGVyaW1ldGVyLmNvbQogIHRvOiBodHRwOi8vaHR0cGJpbgogIGFsbG93ZWRfZG9tYWluczoKICAgIC0gcG9tZXJpdW0uaW8KICBjb3JzX2FsbG93X3ByZWZsaWdodDogdHJ1ZQogIHRpbWVvdXQ6IDMwcwotIGZyb206IGV4dGVybmFsLWh0dHBiaW4uY29ycC5iZXlvbmRwZXJpbWV0ZXIuY29tCiAgdG86IGh0dHBiaW4ub3JnCiAgYWxsb3dlZF9kb21haW5zOgogICAgLSBnbWFpbC5jb20KLSBmcm9tOiB3ZWlyZGx5c3NsLmNvcnAuYmV5b25kcGVyaW1ldGVyLmNvbQogIHRvOiBodHRwOi8vbmV2ZXJzc2wuY29tCiAgYWxsb3dlZF91c2VyczoKICAgIC0gYmRkQHBvbWVyaXVtLmlvCiAgYWxsb3dlZF9ncm91cHM6CiAgICAtIGFkbWlucwogICAgLSBkZXZlbG9wZXJzCi0gZnJvbTogaGVsbG8uY29ycC5iZXlvbmRwZXJpbWV0ZXIuY29tCiAgdG86IGh0dHA6Ly9oZWxsbzo4MDgwCiAgYWxsb3dlZF9ncm91cHM6CiAgICAtIGFkbWlucw==")
			os.Setenv("COOKIE_SECRET", "YixWi1MYh77NMECGGIJQevoonYtVF+ZPRkQZrrmeRqM=")
			defer os.Unsetenv("AUTHENTICATE_SERVICE_URL")
			defer os.Unsetenv("AUTHORIZE_SERVICE_URL")
			defer os.Unsetenv("SHARED_SECRET")
			defer os.Unsetenv("COOKIE_SECRET")
			os.Setenv(tt.envKey, tt.envValue)
			defer os.Unsetenv(tt.envKey)
			_, err := newProxyService(tt.s, mux)
			if (err != nil) != tt.wantErr {
				t.Errorf("newProxyService() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func Test_parseOptions(t *testing.T) {
	tests := []struct {
		name     string
		envKey   string
		envValue string

		want    *Options
		wantErr bool
	}{
		{"no shared secret", "", "", nil, true},
		{"good", "SHARED_SECRET", "YixWi1MYh77NMECGGIJQevoonYtVF+ZPRkQZrrmeRqM=", &Options{Services: "all", SharedKey: "YixWi1MYh77NMECGGIJQevoonYtVF+ZPRkQZrrmeRqM=", LogLevel: "debug"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Setenv(tt.envKey, tt.envValue)
			defer os.Unsetenv(tt.envKey)

			got, err := parseOptions()
			if (err != nil) != tt.wantErr {
				t.Errorf("parseOptions() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseOptions()\n")
				t.Errorf("got: %+v\n", got)
				t.Errorf("want: %+v\n", tt.want)

			}
		})
	}
}
