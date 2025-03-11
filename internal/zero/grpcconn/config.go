package grpcconn

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

	"github.com/pomerium/pomerium/internal/version"
)

// config is the configuration for the gRPC client
type config struct {
	// authority is a host:port string that will be used as the :authority pseudo-header
	authority string
	// requireTLS is whether TLS should be used or cleartext
	requireTLS bool
	// opts are additional options to pass to the gRPC client
	opts []grpc.DialOption
}

// NewConfig returns a new Config from an endpoint string, that has to be in a URL format.
// The endpoint can be either http:// or https:// that will be used to determine whether TLS should be used.
// if port is not specified, it will be inferred from the scheme (80 for http, 443 for https).
func getConfig(
	endpoint string,
	opts ...grpc.DialOption,
) (*config, error) {
	opts = append(opts, grpc.WithUserAgent(version.UserAgent()))
	c := &config{opts: opts}
	err := c.parseEndpoint(endpoint)
	if err != nil {
		return nil, fmt.Errorf("invalid endpoint: %w", err)
	}
	c.buildTLSOptions()
	return c, nil
}

// GetAuthority returns the authority to use in the :authority pseudo-header
func (c *config) GetAuthority() string {
	return c.authority
}

// GetConnectionURI returns connection string conforming to https://github.com/grpc/grpc/blob/master/doc/naming.md
func (c *config) GetConnectionURI() string {
	return "dns:" + c.authority
}

// GetDialTimeout returns the timeout for the dial operation
func (c *config) GetDialTimeout() time.Duration {
	return time.Hour
}

// RequireTLS returns whether TLS should be used or cleartext
func (c *config) RequireTLS() bool {
	return c.requireTLS
}

// GetDialOptions returns the dial options to pass to the gRPC client
func (c *config) GetDialOptions() []grpc.DialOption {
	return c.opts
}

func (c *config) buildTLSOptions() {
	creds := insecure.NewCredentials()
	if c.requireTLS {
		creds = credentials.NewTLS(&tls.Config{
			MinVersion: tls.VersionTLS12,
		})
	}
	c.opts = append(c.opts, grpc.WithTransportCredentials(creds))
}

func (c *config) parseEndpoint(endpoint string) error {
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

	c.authority = host + ":" + port
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
