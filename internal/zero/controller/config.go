package controller

import "time"

// Option configures a controller.
type Option func(*controllerConfig)

type controllerConfig struct {
	apiToken           string
	clusterAPIEndpoint string
	connectAPIEndpoint string

	tmpDir                  string
	bootstrapConfigFileName string

	reconcilerLeaseDuration  time.Duration
	databrokerRequestTimeout time.Duration
}

// WithTmpDir sets the temporary directory to use.
func WithTmpDir(dir string) Option {
	return func(c *controllerConfig) {
		c.tmpDir = dir
	}
}

// WithClusterAPIEndpoint sets the endpoint to use for the cluster API
func WithClusterAPIEndpoint(endpoint string) Option {
	return func(c *controllerConfig) {
		c.clusterAPIEndpoint = endpoint
	}
}

// WithConnectAPIEndpoint sets the endpoint to use for the connect API
func WithConnectAPIEndpoint(endpoint string) Option {
	return func(c *controllerConfig) {
		c.connectAPIEndpoint = endpoint
	}
}

// WithAPIToken sets the API token to use for authentication.
func WithAPIToken(token string) Option {
	return func(c *controllerConfig) {
		c.apiToken = token
	}
}

// WithBootstrapConfigFileName sets the name of the file to store the bootstrap config in.
func WithBootstrapConfigFileName(name string) Option {
	return func(c *controllerConfig) {
		c.bootstrapConfigFileName = name
	}
}

// WithDatabrokerLeaseDuration sets the lease duration for the
func WithDatabrokerLeaseDuration(duration time.Duration) Option {
	return func(c *controllerConfig) {
		c.reconcilerLeaseDuration = duration
	}
}

// WithDatabrokerRequestTimeout sets the timeout for databroker requests.
func WithDatabrokerRequestTimeout(timeout time.Duration) Option {
	return func(c *controllerConfig) {
		c.databrokerRequestTimeout = timeout
	}
}

func newControllerConfig(opts ...Option) *controllerConfig {
	c := new(controllerConfig)

	for _, opt := range []Option{
		WithClusterAPIEndpoint("https://console.pomerium.com/cluster/v1"),
		WithConnectAPIEndpoint("https://connect.pomerium.com"),
		WithBootstrapConfigFileName("/var/cache/pomerium-bootstrap.dat"),
		WithDatabrokerLeaseDuration(time.Minute),
		WithDatabrokerRequestTimeout(time.Second * 30),
	} {
		opt(c)
	}

	for _, opt := range opts {
		opt(c)
	}
	return c
}
