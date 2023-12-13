// Package grpcconn provides a gRPC client with authentication
package grpcconn

import (
	"context"
	"fmt"

	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/logging"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
)

type client struct {
	config        *config
	tokenProvider TokenProviderFn
}

// TokenProviderFn is a function that returns an authorization token
type TokenProviderFn func(ctx context.Context) (string, error)

// New creates a new gRPC client with authentication
func New(
	ctx context.Context,
	endpoint string,
	tokenProvider TokenProviderFn,
) (*grpc.ClientConn, error) {
	cfg, err := getConfig(endpoint)
	if err != nil {
		return nil, err
	}

	cc := &client{
		tokenProvider: tokenProvider,
		config:        cfg,
	}

	conn, err := cc.getGRPCConn(ctx)
	if err != nil {
		return nil, err
	}

	return conn, err
}

func (c *client) getGRPCConn(ctx context.Context) (*grpc.ClientConn, error) {
	opts := append(
		c.config.GetDialOptions(),
		grpc.WithPerRPCCredentials(c),
		grpc.WithDefaultCallOptions(
			grpc.UseCompressor("gzip"),
		),
		grpc.WithChainUnaryInterceptor(
			logging.UnaryClientInterceptor(logging.LoggerFunc(interceptorLogger)),
		),
		grpc.WithStreamInterceptor(
			logging.StreamClientInterceptor(logging.LoggerFunc(interceptorLogger)),
		),
	)

	conn, err := grpc.DialContext(ctx, c.config.GetConnectionURI(), opts...)
	if err != nil {
		return nil, fmt.Errorf("error dialing grpc server: %w", err)
	}

	go c.logConnectionState(ctx, conn)

	return conn, nil
}

// GetRequestMetadata implements credentials.PerRPCCredentials
func (c *client) GetRequestMetadata(ctx context.Context, _ ...string) (map[string]string, error) {
	token, err := c.tokenProvider(ctx)
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

func (c *client) logConnectionState(ctx context.Context, conn *grpc.ClientConn) {
	var state connectivity.State = -1
	for ctx.Err() == nil && state != connectivity.Shutdown {
		_ = conn.WaitForStateChange(ctx, state)
		state = conn.GetState()
		log.Info().
			Str("endpoint", c.config.connectionURI).
			Str("state", state.String()).
			Msg("grpc connection state")
	}
}

func interceptorLogger(ctx context.Context, lvl logging.Level, msg string, fields ...any) {
	l := log.Ctx(ctx).With().Fields(fields).Logger()

	switch lvl {
	case logging.LevelDebug:
		l.Info().Msg(msg)
	case logging.LevelInfo:
		l.Info().Msg(msg)
	case logging.LevelWarn:
		l.Warn().Msg(msg)
	case logging.LevelError:
		l.Error().Msg(msg)
	default:
		panic(fmt.Sprintf("unknown level %v", lvl))
	}
}
