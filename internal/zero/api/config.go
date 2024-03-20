package zero

import (
	"fmt"
	"net/http"
	"time"

	"google.golang.org/grpc"

	"github.com/pomerium/pomerium/internal/featureflags"
)

// Option is a functional option for the SDK
type Option func(*config)

type config struct {
	clusterAPIEndpoint  string
	connectAPIEndpoint  string
	otelEndpoint        string
	apiToken            string
	httpClient          *http.Client
	downloadURLCacheTTL time.Duration
	dialOptions         []grpc.DialOption
}

// WithClusterAPIEndpoint sets the cluster API endpoint
func WithClusterAPIEndpoint(endpoint string) Option {
	return func(cfg *config) {
		cfg.clusterAPIEndpoint = endpoint
	}
}

// WithConnectAPIEndpoint sets the connect API endpoint
func WithConnectAPIEndpoint(endpoint string) Option {
	return func(cfg *config) {
		cfg.connectAPIEndpoint = endpoint
	}
}

// WithOTELEndpoint sets the OTEL API endpoint
func WithOTELEndpoint(endpoint string) Option {
	return func(cfg *config) {
		cfg.otelEndpoint = endpoint
	}
}

// WithAPIToken sets the API token
func WithAPIToken(token string) Option {
	return func(cfg *config) {
		cfg.apiToken = token
	}
}

// WithHTTPClient sets the HTTP client
func WithHTTPClient(client *http.Client) Option {
	return func(cfg *config) {
		cfg.httpClient = client
	}
}

// WithDownloadURLCacheTTL sets the minimum TTL for download URL cache entries
func WithDownloadURLCacheTTL(ttl time.Duration) Option {
	return func(cfg *config) {
		cfg.downloadURLCacheTTL = ttl
	}
}

func newConfig(opts ...Option) (*config, error) {
	cfg := new(config)
	for _, opt := range []Option{
		WithHTTPClient(http.DefaultClient),
		WithDownloadURLCacheTTL(15 * time.Minute),
	} {
		opt(cfg)
	}

	if !featureflags.IsSet(featureflags.GRPCConnectDisableKeepalive) {
		cfg.dialOptions = append(cfg.dialOptions, grpc.WithKeepaliveParams(connectClientKeepaliveParams))
	}

	for _, opt := range opts {
		opt(cfg)
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *config) validate() error {
	if c.clusterAPIEndpoint == "" {
		return fmt.Errorf("cluster API endpoint is required")
	}
	if c.connectAPIEndpoint == "" {
		return fmt.Errorf("connect API endpoint is required")
	}
	if c.otelEndpoint == "" {
		return fmt.Errorf("OTEL API endpoint is required")
	}
	if c.apiToken == "" {
		return fmt.Errorf("API token is required")
	}
	if c.httpClient == nil {
		return fmt.Errorf("HTTP client is required")
	}
	return nil
}
