package main

import (
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/signal"
	"reflect"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/pomerium/pomerium/internal/config"
	"github.com/pomerium/pomerium/internal/httputil"
)

func Test_newAuthenticateService(t *testing.T) {
	mux := httputil.NewRouter()

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
			testOpts, err := config.NewOptions("https://authenticate.example", "https://authorize.example", nil)
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

			_, err = newAuthenticateService(*testOpts, mux)
			if (err != nil) != tt.wantErr {
				t.Errorf("newAuthenticateService() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

		})
	}
}

func Test_newAuthorizeService(t *testing.T) {
	os.Clearenv()

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
			testOpts, err := config.NewOptions("https://some.example", "https://some.example", nil)
			if err != nil {
				t.Fatal(err)
			}
			testOpts.InsecureServer = true
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
			var wg sync.WaitGroup
			_, err = newAuthorizeService(*testOpts, &wg)
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
			mux := httputil.NewRouter()
			testOpts, err := config.NewOptions("https://authenticate.example", "https://authorize.example", nil)
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

func Test_newGlobalRouter(t *testing.T) {
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
	req := httptest.NewRequest(http.MethodGet, "/404", nil)
	rr := httptest.NewRecorder()
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `OK`)
	})

	out := newGlobalRouter(&o)
	out.Handle("/404", h)

	out.ServeHTTP(rr, req)
	expected := fmt.Sprintf("OK")
	body := rr.Body.String()

	if body != expected {
		t.Errorf("handler returned unexpected body: got %v want %v", body, expected)
	}
}

func Test_httpServerOptions(t *testing.T) {
	tests := []struct {
		name string
		opt  *config.Options
		want *httputil.ServerOptions
	}{
		{"simple convert", &config.Options{Addr: ":80"}, &httputil.ServerOptions{Addr: ":80"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if diff := cmp.Diff(httpServerOptions(tt.opt), tt.want); diff != "" {
				t.Errorf("httpServerOptions() = \n %s", diff)
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
			var wg sync.WaitGroup

			setupMetrics(tt.opt, &wg)
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
			var wg sync.WaitGroup

			signal.Notify(c, syscall.SIGINT)
			defer signal.Stop(c)
			setupHTTPRedirectServer(tt.opt, &wg)
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

func Test_run(t *testing.T) {
	tests := []struct {
		name           string
		versionFlag    bool
		configFileFlag string
		wantErr        bool
	}{
		{"simply print version", true, "", false},
		{"nil configuration", false, "", true},
		{"simple proxy", false, `
		{ 
			"address": ":9433",
			"grpc_address": ":9444",
			"grpc_insecure": true,
			"insecure_server": true,
			"authorize_service_url": "https://authorize.corp.example",
			"authenticate_service_url": "https://authenticate.corp.example",
			"shared_secret": "YixWi1MYh77NMECGGIJQevoonYtVF+ZPRkQZrrmeRqM=",
			"cookie_secret": "zixWi1MYh77NMECGGIJQevoonYtVF+ZPRkQZrrmeRqM=",
			"services": "proxy",
			"policy": [{ "from": "https://pomerium.io", "to": "https://httpbin.org" }]
		  }	  
		`, false},
		{"simple authorize", false, `
		{ 
			"address": ":9433",
			"grpc_address": ":9444",
			"grpc_insecure": false,
			"insecure_server": true,
			"authorize_service_url": "https://authorize.corp.example",
			"authenticate_service_url": "https://authenticate.corp.example",
			"shared_secret": "YixWi1MYh77NMECGGIJQevoonYtVF+ZPRkQZrrmeRqM=",
			"cookie_secret": "zixWi1MYh77NMECGGIJQevoonYtVF+ZPRkQZrrmeRqM=",
			"services": "authorize",
			"policy": [{ "from": "https://pomerium.io", "to": "https://httpbin.org" }]
		  }	  
		`, false},
		{"bad proxy no authenticate url", false, `
		{ 
			"address": ":9433",
			"grpc_address": ":9444",
			"insecure_server": true,
			"authorize_service_url": "https://authorize.corp.example",
			"shared_secret": "YixWi1MYh77NMECGGIJQevoonYtVF+ZPRkQZrrmeRqM=",
			"cookie_secret": "zixWi1MYh77NMECGGIJQevoonYtVF+ZPRkQZrrmeRqM=",
			"services": "proxy",
			"policy": [{ "from": "https://pomerium.io", "to": "https://httpbin.org" }]
		  }	  
		`, true},
		{"bad authenticate no cookie secret", false, `
		{ 
			"address": ":9433",
			"grpc_address": ":9444",
			"insecure_server": true,
			"authenticate_service_url": "https://authenticate.corp.example",
			"shared_secret": "YixWi1MYh77NMECGGIJQevoonYtVF+ZPRkQZrrmeRqM=",
			"services": "authenticate",
			"policy": [{ "from": "https://pomerium.io", "to": "https://httpbin.org" }]
		  }	  
		`, true},
		{"bad authorize service bad shared key", false, `
		{ 
			"address": ":9433",
			"grpc_address": ":9444",
			"insecure_server": true,
			"authorize_service_url": "https://authorize.corp.example",
			"shared_secret": " ",
			"cookie_secret": "zixWi1MYh77NMECGGIJQevoonYtVF+ZPRkQZrrmeRqM=",
			"services": "authorize",
			"policy": [{ "from": "https://pomerium.io", "to": "https://httpbin.org" }]
		  }	  
		`, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			versionFlag = &tt.versionFlag
			tmpFile, err := ioutil.TempFile(os.TempDir(), "*.json")
			if err != nil {
				t.Fatal("Cannot create temporary file", err)
			}
			defer os.Remove(tmpFile.Name())
			fn := tmpFile.Name()
			if _, err := tmpFile.Write([]byte(tt.configFileFlag)); err != nil {
				tmpFile.Close()
				t.Fatal(err)
			}
			configFile = &fn
			proc, err := os.FindProcess(os.Getpid())
			if err != nil {
				t.Fatal(err)
			}
			go func() {
				time.Sleep(time.Millisecond * 500)
				proc.Signal(os.Interrupt)
			}()

			err = run()
			if (err != nil) != tt.wantErr {
				t.Errorf("run() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
