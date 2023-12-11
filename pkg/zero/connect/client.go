package connect

import (
	"context"
	"fmt"
	"time"

	"google.golang.org/grpc"
	grpc_backoff "google.golang.org/grpc/backoff"
)

const (
	defaultDialTimeout = time.Hour
)

type client struct {
	config        *Config
	tokenProvider TokenProviderFn
	minTokenTTL   time.Duration
}

// TokenProviderFn is a function that returns a token that is expected to be valid for at least minTTL
type TokenProviderFn func(ctx context.Context, minTTL time.Duration) (string, error)

// NewAuthorizedConnectClient creates a new gRPC client for the connect service
func NewAuthorizedConnectClient(
	ctx context.Context,
	endpoint string,
	tokenProvider TokenProviderFn,
) (ConnectClient, error) {
	cfg, err := NewConfig(endpoint)
	if err != nil {
		return nil, err
	}

	cc := &client{
		tokenProvider: tokenProvider,
		config:        cfg,
		// streaming connection would reset based on token duration,
		// so we need it be close to max duration 1hr
		minTokenTTL: time.Minute * 55,
	}

	grpcConn, err := cc.getGRPCConn(ctx)
	if err != nil {
		return nil, err
	}

	return NewConnectClient(grpcConn), nil
}

func (c *client) getGRPCConn(ctx context.Context) (*grpc.ClientConn, error) {
	conn, err := grpc.DialContext(ctx,
		c.config.GetConnectionURI(),
		append(c.config.GetDialOptions(),
			grpc.WithPerRPCCredentials(c),
			grpc.WithConnectParams(grpc.ConnectParams{
				Backoff: grpc_backoff.DefaultConfig,
				// the MinConnectTimeout is confusing and is actually the max timeout as per grpc implementation
				MinConnectTimeout: c.config.GetDialTimeout(),
			}),
		)...)
	if err != nil {
		return nil, fmt.Errorf("error dialing grpc server: %w", err)
	}
	return conn, nil
}

// GetRequestMetadata implements credentials.PerRPCCredentials
func (c *client) GetRequestMetadata(ctx context.Context, _ ...string) (map[string]string, error) {
	token, err := c.tokenProvider(ctx, c.minTokenTTL)
	if err != nil {
		return nil, err
	}
	return map[string]string{
		"authorization": fmt.Sprintf("Bearer %s", token),
	}, nil
}

// RequireTransportSecurity implements credentials.PerRPCCredentials
func (c *client) RequireTransportSecurity() bool {
	return c.config.RequireTLS()
}
