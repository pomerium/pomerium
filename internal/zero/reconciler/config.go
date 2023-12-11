// Package reconciler syncs the state of resource bundles between the cloud and the databroker.
package reconciler

import (
	"net/http"
	"os"
	"time"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	sdk "github.com/pomerium/pomerium/pkg/zero"
)

// reconcilerConfig contains the configuration for the resource bundles reconciler.
type reconcilerConfig struct {
	api *sdk.API

	databrokerClient databroker.DataBrokerServiceClient
	databrokerRPS    int

	tmpDir string

	httpClient *http.Client

	checkForUpdateIntervalWhenDisconnected time.Duration
	checkForUpdateIntervalWhenConnected    time.Duration

	syncBackoffMaxInterval time.Duration
}

// Option configures the resource bundles reconciler
type Option func(*reconcilerConfig)

// WithTemporaryDirectory configures the resource bundles client to use a temporary directory for
// downloading files.
func WithTemporaryDirectory(path string) Option {
	return func(cfg *reconcilerConfig) {
		cfg.tmpDir = path
	}
}

// WithAPI configures the cluster api client.
func WithAPI(client *sdk.API) Option {
	return func(cfg *reconcilerConfig) {
		cfg.api = client
	}
}

// WithDataBrokerClient configures the databroker client.
func WithDataBrokerClient(client databroker.DataBrokerServiceClient) Option {
	return func(cfg *reconcilerConfig) {
		cfg.databrokerClient = client
	}
}

// WithDownloadHTTPClient configures the http client used for downloading files.
func WithDownloadHTTPClient(client *http.Client) Option {
	return func(cfg *reconcilerConfig) {
		cfg.httpClient = client
	}
}

// WithDatabrokerRPSLimit configures the maximum number of requests per second to the databroker.
func WithDatabrokerRPSLimit(rps int) Option {
	return func(cfg *reconcilerConfig) {
		cfg.databrokerRPS = rps
	}
}

// WithCheckForUpdateIntervalWhenDisconnected configures the interval at which the reconciler will check
// for updates when disconnected from the cloud.
func WithCheckForUpdateIntervalWhenDisconnected(interval time.Duration) Option {
	return func(cfg *reconcilerConfig) {
		cfg.checkForUpdateIntervalWhenDisconnected = interval
	}
}

// WithCheckForUpdateIntervalWhenConnected configures the interval at which the reconciler will check
// for updates when connected to the cloud.
func WithCheckForUpdateIntervalWhenConnected(interval time.Duration) Option {
	return func(cfg *reconcilerConfig) {
		cfg.checkForUpdateIntervalWhenConnected = interval
	}
}

// WithSyncBackoffMaxInterval configures the maximum interval between sync attempts.
func WithSyncBackoffMaxInterval(interval time.Duration) Option {
	return func(cfg *reconcilerConfig) {
		cfg.syncBackoffMaxInterval = interval
	}
}

func newConfig(opts ...Option) *reconcilerConfig {
	cfg := &reconcilerConfig{}
	for _, opt := range []Option{
		WithTemporaryDirectory(os.TempDir()),
		WithDownloadHTTPClient(http.DefaultClient),
		WithDatabrokerRPSLimit(1_000),
		WithCheckForUpdateIntervalWhenDisconnected(time.Minute * 5),
		WithCheckForUpdateIntervalWhenConnected(time.Hour),
		WithSyncBackoffMaxInterval(time.Minute),
	} {
		opt(cfg)
	}

	for _, opt := range opts {
		opt(cfg)
	}

	return cfg
}
