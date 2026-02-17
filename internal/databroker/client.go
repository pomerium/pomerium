package databroker

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"
	oteltrace "go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/telemetry"
	"github.com/pomerium/pomerium/pkg/grpcutil"
)

// A ClientManager manages client connections for gRPC.
type ClientManager struct {
	telemetry telemetry.Component
	grpcutil.ClientManager

	mu        sync.Mutex
	sharedKey []byte
	caPEM     []byte
}

// NewClientManager creates a new ClientManager.
func NewClientManager(tracerProvider oteltrace.TracerProvider) *ClientManager {
	return &ClientManager{
		telemetry:     *telemetry.NewComponent(tracerProvider, zerolog.TraceLevel, "databroker-grpc-client-manager"),
		ClientManager: grpcutil.NewClientManager(tracerProvider),
	}
}

func (mgr *ClientManager) OnConfigChange(ctx context.Context, cfg *config.Config) {
	ctx, op := mgr.telemetry.Start(ctx, "OnConfigChange")
	defer op.Complete()

	sharedKey, err := cfg.Options.GetSharedKey()
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("error getting shared key")
		_ = op.Failure(err)
		return
	}

	caPEM, err := cfg.AllCertificateAuthoritiesPEM()
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("error getting combined certificate authority pem")
		_ = op.Failure(err)
		return
	}

	mgr.mu.Lock()
	defer mgr.mu.Unlock()

	// if the shared key and the certificate authority hasn't changed,
	// there's not anything to update
	if bytes.Equal(mgr.sharedKey, sharedKey) &&
		bytes.Equal(mgr.caPEM, caPEM) {
		return
	}
	mgr.sharedKey = sharedKey
	mgr.caPEM = caPEM

	cfg = cfg.Clone()
	mgr.UpdateOptions(grpcutil.WithClientManagerNewClient(func(target string, options ...grpc.DialOption) (*grpc.ClientConn, error) {
		return mgr.NewClientForConfig(cfg, target, options...)
	}))
}

// NewClientForConfig creates a new client for the given config.
func (mgr *ClientManager) NewClientForConfig(cfg *config.Config, rawURL string, options ...grpc.DialOption) (*grpc.ClientConn, error) {
	ctx, op := mgr.telemetry.Start(context.Background(), "NewClientForConfig")
	defer op.Complete()

	log.Ctx(ctx).Info().Msgf("connecting to %s", rawURL)

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
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			// !! should not exceed grpc.Server keepalive policy enforcement (default 5 mins)
			Time:                6 * time.Minute,
			Timeout:             20 * time.Second,
			PermitWithoutStream: true,
		}),
		grpc.WithChainStreamInterceptor(
			grpcutil.WithStreamSignedJWT(func() []byte {
				return sharedKey
			}),
		),
		grpc.WithChainUnaryInterceptor(
			grpcutil.WithUnarySignedJWT(func() []byte {
				return sharedKey
			}),
		),
	)
	if u.Scheme == "http" {
		options = append(options, grpc.WithTransportCredentials(insecure.NewCredentials()))
	} else {
		rootCAs, err := cfg.GetCertificatePool()
		if err != nil {
			return nil, fmt.Errorf("error loading certificate pool for gRPC connection")
		}
		options = append(options, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
			RootCAs:    rootCAs,
			MinVersion: tls.VersionTLS12,
		})))
	}

	return grpc.NewClient(target, options...)
}
