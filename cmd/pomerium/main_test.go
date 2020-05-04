package main

import (
	"io/ioutil"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/httputil"
)

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
		name    string
		opt     *config.Options
		wantErr bool
	}{
		{"dont register anything", &config.Options{}, false},
		{"good redirect server", &config.Options{HTTPRedirectAddr: "localhost:0"}, false},
		{"bad redirect server port", &config.Options{HTTPRedirectAddr: "localhost:-1"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := make(chan os.Signal, 1)
			var wg sync.WaitGroup

			signal.Notify(c, syscall.SIGINT)
			defer signal.Stop(c)
			err := setupHTTPRedirectServer(tt.opt, &wg)
			if (err != nil) != tt.wantErr {
				t.Errorf("run() error = %v, wantErr %v", err, tt.wantErr)
			}

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
	os.Clearenv()
	t.Parallel()
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
			"shared_secret": "^^^",
			"cookie_secret": "zixWi1MYh77NMECGGIJQevoonYtVF+ZPRkQZrrmeRqM=",
			"services": "authorize",
			"policy": [{ "from": "https://pomerium.io", "to": "https://httpbin.org" }]
		  }
		`, true},
		{"bad http port", false, `
		{
			"address": ":-1",
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
		`, true},
		{"bad redirect port", false, `
		{
			"address": ":9433",
			"http_redirect_addr":":-1",
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
		`, true},
		{"bad metrics port ", false, `
		{
			"address": ":9433",
			"metrics_address": ":-1",
			"grpc_insecure": true,
			"insecure_server": true,
			"authorize_service_url": "https://authorize.corp.example",
			"authenticate_service_url": "https://authenticate.corp.example",
			"shared_secret": "YixWi1MYh77NMECGGIJQevoonYtVF+ZPRkQZrrmeRqM=",
			"cookie_secret": "zixWi1MYh77NMECGGIJQevoonYtVF+ZPRkQZrrmeRqM=",
			"services": "proxy",
			"policy": [{ "from": "https://pomerium.io", "to": "https://httpbin.org" }]
		  }
		`, true},
		{"malformed tracing provider", false, `
		{
			"tracing_provider": "bad tracing provider",
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
		`, true},
		// {"simple cache", false, `
		// {
		// 	"address": ":9433",
		// 	"grpc_address": ":9444",
		// 	"grpc_insecure": false,
		// 	"insecure_server": true,
		// 	"cache_service_url": "https://authorize.corp.example",
		// 	"authenticate_service_url": "https://authenticate.corp.example",
		// 	"shared_secret": "YixWi1MYh77NMECGGIJQevoonYtVF+ZPRkQZrrmeRqM=",
		// 	"cookie_secret": "zixWi1MYh77NMECGGIJQevoonYtVF+ZPRkQZrrmeRqM=",
		// 	"services": "cache",
		// 	"cache_store": "bolt",
		// 	"policy": [{ "from": "https://pomerium.io", "to": "https://httpbin.org" }]
		//   }
		// `, false},
		// {"malformed cache", false, `
		// {
		// 	"address": ":9433",
		// 	"grpc_address": ":9444",
		// 	"grpc_insecure": false,
		// 	"insecure_server": true,
		// 	"cache_service_url": "https://authorize.corp.example",
		// 	"authenticate_service_url": "https://authenticate.corp.example",
		// 	"shared_secret": "YixWi1MYh77NMECGGIJQevoonYtVF+ZPRkQZrrmeRqM=",
		// 	"cookie_secret": "zixWi1MYh77NMECGGIJQevoonYtVF+ZPRkQZrrmeRqM=",
		// 	"services": "cache",
		// 	"cache_store": "bad bolt",
		// 	"policy": [{ "from": "https://pomerium.io", "to": "https://httpbin.org" }]
		//   }
		// `, true},
		// {"bad cache port", false, `
		// {
		// 	"address": ":9433",
		// 	"grpc_address": ":9999999",
		// 	"grpc_insecure": false,
		// 	"insecure_server": true,
		// 	"cache_service_url": "https://authorize.corp.example",
		// 	"authenticate_service_url": "https://authenticate.corp.example",
		// 	"shared_secret": "YixWi1MYh77NMECGGIJQevoonYtVF+ZPRkQZrrmeRqM=",
		// 	"cookie_secret": "zixWi1MYh77NMECGGIJQevoonYtVF+ZPRkQZrrmeRqM=",
		// 	"services": "cache",
		// 	"cache_store": "bolt",
		// 	"policy": [{ "from": "https://pomerium.io", "to": "https://httpbin.org" }]
		//   }
		// `, true},
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
