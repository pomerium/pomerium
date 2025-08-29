package databroker

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"net/url"
	"strings"
	"sync"

	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/logging"
	oteltrace "go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/grpcutil"
)

// A ClientManager manages client connections for gRPC.
type ClientManager struct {
	grpcutil.ClientManager

	mu        sync.RWMutex
	sharedKey []byte
}

// NewClientManager creates a new ClientManager.
func NewClientManager(tracerProvider oteltrace.TracerProvider) *ClientManager {
	return &ClientManager{
		ClientManager: grpcutil.NewClientManager(tracerProvider),
	}
}

func (mgr *ClientManager) OnConfigChange(ctx context.Context, cfg *config.Config) {
	sharedKey, err := cfg.Options.GetSharedKey()
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("databroker/client-connection-manager: error getting shared key")
		return
	}

	mgr.mu.Lock()
	defer mgr.mu.Unlock()

	// if the shared key hasn't changed, there's not anything to update
	if bytes.Equal(mgr.sharedKey, sharedKey) {
		return
	}
	mgr.sharedKey = sharedKey

	cfg = cfg.Clone()
	mgr.UpdateOptions(grpcutil.WithClientManagerNewClient(func(target string, options ...grpc.DialOption) (*grpc.ClientConn, error) {
		return NewClientForConfig(cfg, target, options...)
	}))
}

func NewClientForConfig(cfg *config.Config, rawURL string, options ...grpc.DialOption) (*grpc.ClientConn, error) {
	sharedKey, err := cfg.Options.GetSharedKey()
	if err != nil {
		return nil, err
	}

	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}

	target := u.Host
	if !strings.Contains(target, ":") {
		if u.Scheme == "http" {
			target += ":80"
		} else {
			target += ":443"
		}
	}

	options = append(options,
		grpc.WithChainStreamInterceptor(
			logging.StreamClientInterceptor(logging.LoggerFunc(interceptorLogger)),
			grpcutil.WithStreamSignedJWT(func() []byte {
				return sharedKey
			}),
		),
		grpc.WithChainUnaryInterceptor(
			logging.UnaryClientInterceptor(logging.LoggerFunc(interceptorLogger)),
			grpcutil.WithUnarySignedJWT(func() []byte {
				return sharedKey
			}),
		),
	)
	if u.Scheme == "http" {
		options = append(options, grpc.WithTransportCredentials(insecure.NewCredentials()))
	} else {
		options = append(options, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
			InsecureSkipVerify: true,
		})))
	}

	return grpc.NewClient(target, options...)
}

func interceptorLogger(ctx context.Context, lvl logging.Level, msg string, fields ...any) {
	l := log.Ctx(ctx).With().Fields(fields).Logger()

	switch lvl {
	case logging.LevelDebug:
		l.Debug().Msg(msg)
	case logging.LevelInfo:
		l.Debug().Msg(msg)
	case logging.LevelWarn:
		l.Warn().Msg(msg)
	case logging.LevelError:
		l.Error().Msg(msg)
	default:
		panic(fmt.Sprintf("unknown level %v", lvl))
	}
}
