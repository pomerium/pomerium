package pomerium_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/pkg/cmd/pomerium"
	"github.com/pomerium/pomerium/pkg/envoy/files"
)

func Test_run(t *testing.T) {
	os.Clearenv()

	run := func(ctx context.Context, configFile string) error {
		src, err := config.NewFileOrEnvironmentSource(configFile, files.FullVersion())
		if err != nil {
			return err
		}

		return pomerium.Run(ctx, src)
	}

	tests := []struct {
		name           string
		configFileFlag string
		check          func(require.TestingT, error, ...any)
	}{
		{"nil configuration", "", require.Error},
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
		`, require.Error},
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
		`, require.Error},
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
		`, require.Error},
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
		`, require.Error},
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
		`, require.Error},
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
		`, require.Error},
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
		`, require.Error},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpFile, err := os.CreateTemp(os.TempDir(), "*.json")
			if err != nil {
				t.Fatal("Cannot create temporary file", err)
			}
			defer func() { _ = os.Remove(tmpFile.Name()) }()
			fn := tmpFile.Name()
			if _, err := tmpFile.Write([]byte(tt.configFileFlag)); err != nil {
				tmpFile.Close()
				t.Fatal(err)
			}
			configFile := fn

			ctx, clearTimeout := context.WithTimeout(context.Background(), 500*time.Millisecond)
			defer clearTimeout()

			tt.check(t, run(ctx, configFile))
		})
	}
}
