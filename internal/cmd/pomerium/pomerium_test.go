package pomerium

import (
	"context"
	"io/ioutil"
	"os"
	"testing"
	"time"
)

func Test_run(t *testing.T) {
	os.Clearenv()
	t.Parallel()
	tests := []struct {
		name           string
		configFileFlag string
		wantErr        bool
	}{
		{"nil configuration", "", true},
		{"bad proxy no authenticate url", `
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
		{"bad authenticate no cookie secret", `
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
		{"bad authorize service bad shared key", `
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
		{"bad http port", `
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
		{"bad redirect port", `
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
		{"bad metrics port ", `
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
		{"malformed tracing provider", `
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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
			configFile := fn

			ctx, clearTimeout := context.WithTimeout(context.Background(), 500*time.Millisecond)
			defer clearTimeout()

			err = Run(ctx, configFile)
			if (err != nil) != tt.wantErr {
				t.Errorf("run() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
