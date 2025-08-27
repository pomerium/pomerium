package controller

import (
	"time"

	oteltrace "go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
)

// Option configures a controller.
type Option func(*controllerConfig)

type controllerConfig struct {
	apiToken           string
	clusterAPIEndpoint string
	connectAPIEndpoint string
	otelEndpoint       string

	tmpDir                      string
	bootstrapConfigFileName     *string
	bootstrapConfigWritebackURI *string

	reconcilerLeaseDuration  time.Duration
	databrokerRequestTimeout time.Duration
	shutdownTimeout          time.Duration
	tracerProvider           oteltrace.TracerProvider
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

// WithOTELAPIEndpoint sets the endpoint to use for the OTEL API
func WithOTELAPIEndpoint(endpoint string) Option {
	return func(c *controllerConfig) {
		c.otelEndpoint = endpoint
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
		c.bootstrapConfigFileName = &name
	}
}

// WithBootstrapConfigWritebackURI sets the URI to use for persisting changes made to the
// bootstrap config read from a filename specified by WithBootstrapConfigFileName.
// Accepts a URI with a non-empty scheme and path.
//
// The following schemes are supported:
//
// # file
//
// Writes the config to a file on disk.
//
// Example: "file:///path/to/file" would write the config to "/path/to/file"
// on disk.
//
// # secret
//
// Writes the config to a Kubernetes Secret. Uses the format
// "secret://namespace/name/key".
//
// Example: "secret://pomerium/bootstrap/bootstrap.dat" would
// write the config to a secret named "bootstrap" in the "pomerium" namespace,
// under the key "bootstrap.dat", as if created with the following YAML:
//
//	apiVersion: v1
//	kind: Secret
//	metadata:
//	  name: bootstrap
//	  namespace: pomerium
//	data:
//	  bootstrap.dat: <base64 encoded config>
func WithBootstrapConfigWritebackURI(uri string) Option {
	return func(c *controllerConfig) {
		c.bootstrapConfigWritebackURI = &uri
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

// WithShutdownTimeout sets the timeout for shutting down and cleanup.
func WithShutdownTimeout(timeout time.Duration) Option {
	return func(c *controllerConfig) {
		c.shutdownTimeout = timeout
	}
}

// WithTracerProvider sets the tracer provider in the config.
func WithTracerProvider(tracerProvider oteltrace.TracerProvider) Option {
	return func(cfg *controllerConfig) {
		cfg.tracerProvider = tracerProvider
	}
}

func newControllerConfig(opts ...Option) *controllerConfig {
	c := new(controllerConfig)

	for _, opt := range []Option{
		WithClusterAPIEndpoint("https://console.pomerium.com/cluster/v1"),
		WithConnectAPIEndpoint("https://connect.pomerium.com"),
		WithDatabrokerLeaseDuration(time.Second * 30),
		WithDatabrokerRequestTimeout(time.Second * 30),
		WithShutdownTimeout(time.Second * 10),
		WithTracerProvider(noop.NewTracerProvider()),
	} {
		opt(c)
	}

	for _, opt := range opts {
		opt(c)
	}
	return c
}
