package connect

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

// Config is the configuration for the gRPC client
type Config struct {
	connectionURI string
	// requireTLS is whether TLS should be used or cleartext
	requireTLS bool
	// opts are additional options to pass to the gRPC client
	opts []grpc.DialOption
}

// NewConfig returns a new Config from an endpoint string, that has to be in a URL format.
// The endpoint can be either http:// or https:// that will be used to determine whether TLS should be used.
// if port is not specified, it will be inferred from the scheme (80 for http, 443 for https).
func NewConfig(endpoint string) (*Config, error) {
	c := new(Config)
	err := c.parseEndpoint(endpoint)
	if err != nil {
		return nil, fmt.Errorf("invalid endpoint: %w", err)
	}
	c.buildTLSOptions()
	return c, nil
}

// GetConnectionURI returns connection string conforming to https://github.com/grpc/grpc/blob/master/doc/naming.md
func (c *Config) GetConnectionURI() string {
	return c.connectionURI
}

// GetDialTimeout returns the timeout for the dial operation
func (c *Config) GetDialTimeout() time.Duration {
	return defaultDialTimeout
}

// RequireTLS returns whether TLS should be used or cleartext
func (c *Config) RequireTLS() bool {
	return c.requireTLS
}

// GetDialOptions returns the dial options to pass to the gRPC client
func (c *Config) GetDialOptions() []grpc.DialOption {
	return c.opts
}

func (c *Config) buildTLSOptions() {
	creds := insecure.NewCredentials()
	if c.requireTLS {
		creds = credentials.NewTLS(&tls.Config{
			MinVersion: tls.VersionTLS12,
		})
	}
	c.opts = append(c.opts, grpc.WithTransportCredentials(creds))
}

func (c *Config) parseEndpoint(endpoint string) error {
	u, err := url.Parse(endpoint)
	if err != nil {
		return fmt.Errorf("error parsing endpoint url: %w", err)
	}

	if u.Path != "" && u.Path != "/" {
		return fmt.Errorf("endpoint path is not supported: %s", u.Path)
	}

	host, port, err := splitHostPort(u.Host)
	if err != nil {
		return fmt.Errorf("error splitting host and port: %w", err)
	}

	var requireTLS bool
	if u.Scheme == "http" {
		requireTLS = false
		if port == "" {
			port = "80"
		}
	} else if u.Scheme == "https" {
		requireTLS = true
		if port == "" {
			port = "443"
		}
	} else {
		return fmt.Errorf("unsupported url scheme: %s", u.Scheme)
	}

	c.connectionURI = fmt.Sprintf("dns:%s:%s", host, port)
	c.requireTLS = requireTLS

	return nil
}

var rePort = regexp.MustCompile(`:(\d+)$`)

func splitHostPort(hostport string) (host, port string, err error) {
	if hostport == "" {
		return "", "", fmt.Errorf("empty hostport")
	}
	if rePort.MatchString(hostport) {
		host, port, err = net.SplitHostPort(hostport)
		if host == "" {
			return "", "", fmt.Errorf("empty host")
		}
		if port == "" {
			return "", "", fmt.Errorf("empty port")
		}
		return host, port, err
	}
	return hostport, "", nil
}
