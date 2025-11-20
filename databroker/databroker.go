// Package databroker is a Pomerium service that handles the storage of data in Pomerium.
// It communicates over gRPC with other Pomerium services and can be configured to use a
// number of different backend databroker stores.
package databroker

import (
	"context"
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	oteltrace "go.opentelemetry.io/otel/trace"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/databroker"
	"github.com/pomerium/pomerium/internal/events"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/version"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	"github.com/pomerium/pomerium/pkg/envoy/files"
	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
	registrypb "github.com/pomerium/pomerium/pkg/grpc/registry"
	"github.com/pomerium/pomerium/pkg/grpcutil"
	"github.com/pomerium/pomerium/pkg/health"
	"github.com/pomerium/pomerium/pkg/identity"
	"github.com/pomerium/pomerium/pkg/identity/manager"
	"github.com/pomerium/pomerium/pkg/telemetry/trace"
)

// DataBroker represents the databroker service.
type DataBroker struct {
	cfg         *databrokerConfig
	srv         databroker.Server
	identityMgr *manager.Manager
	eventsMgr   *events.Manager

	localListener       net.Listener
	localGRPCServer     *grpc.Server
	localGRPCConnection *grpc.ClientConn
	sharedKey           atomic.Pointer[[]byte]
	tracerProvider      oteltrace.TracerProvider
	tracer              oteltrace.Tracer
}

// New creates a new databroker service.
func New(ctx context.Context, cfg *config.Config, eventsMgr *events.Manager, options ...Option) (*DataBroker, error) {
	localListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}

	ui, si := grpcutil.AttachMetadataInterceptors(
		metadata.Pairs(
			grpcutil.MetadataKeyEnvoyVersion, files.FullVersion(),
			grpcutil.MetadataKeyPomeriumVersion, version.FullVersion(),
		),
	)

	tracerProvider := trace.NewTracerProvider(ctx, "Data Broker")
	tracer := tracerProvider.Tracer(trace.PomeriumCoreTracer)
	// No metrics handler because we have one in the control plane.  Add one
	// if we no longer register with that grpc Server
	localGRPCServer := grpc.NewServer(
		grpc.StatsHandler(otelgrpc.NewServerHandler(otelgrpc.WithTracerProvider(tracerProvider))),
		grpc.ChainStreamInterceptor(log.StreamServerInterceptor(log.Ctx(ctx)), si),
		grpc.ChainUnaryInterceptor(log.UnaryServerInterceptor(log.Ctx(ctx)), ui),
	)

	srv := NewServer(tracerProvider, cfg)

	d := &DataBroker{
		cfg:             getConfig(options...),
		srv:             srv,
		localListener:   localListener,
		localGRPCServer: localGRPCServer,
		eventsMgr:       eventsMgr,
		tracerProvider:  tracerProvider,
		tracer:          tracer,
	}
	d.Register(d.localGRPCServer)

	sharedKey, err := cfg.Options.GetSharedKey()
	if err != nil {
		return nil, err
	}
	d.sharedKey.Store(&sharedKey)

	clientDialOptions := []grpc.DialOption{
		grpc.WithInsecure(),
		grpc.WithChainUnaryInterceptor(grpcutil.WithUnarySignedJWT(func() []byte {
			return *d.sharedKey.Load()
		})),
		grpc.WithChainStreamInterceptor(grpcutil.WithStreamSignedJWT(func() []byte {
			return *d.sharedKey.Load()
		})),
		grpc.WithStatsHandler(otelgrpc.NewClientHandler(otelgrpc.WithTracerProvider(tracerProvider))),
	}

	ctx = log.WithContext(ctx, func(c zerolog.Context) zerolog.Context {
		return c.Str("service", "databroker").Str("config-source", "bootstrap")
	})
	d.localGRPCConnection, err = grpc.DialContext(
		ctx,
		localListener.Addr().String(),
		clientDialOptions...,
	)
	if err != nil {
		return nil, err
	}

	err = d.update(ctx, cfg)
	if err != nil {
		return nil, err
	}

	return d, nil
}

// OnConfigChange is called whenever configuration is changed.
func (d *DataBroker) OnConfigChange(ctx context.Context, cfg *config.Config) {
	err := d.update(ctx, cfg)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("databroker: error updating configuration")
	}

	d.srv.OnConfigChange(ctx, cfg)
}

// Register registers all the gRPC services with the given server.
func (d *DataBroker) Register(grpcServer *grpc.Server) {
	databrokerpb.RegisterCheckpointServiceServer(grpcServer, d.srv)
	databrokerpb.RegisterDataBrokerServiceServer(grpcServer, d.srv)
	registrypb.RegisterRegistryServer(grpcServer, d.srv)
}

// Run runs the databroker components.
func (d *DataBroker) Run(ctx context.Context) error {
	defer func() {
		health.ReportTerminating(health.DatabrokerCluster)
		d.srv.Stop()
	}()
	eg, ctx := errgroup.WithContext(ctx)
	eg.Go(func() error {
		return grpcutil.ServeWithGracefulStop(ctx, d.localGRPCServer, d.localListener, time.Second*5)
	})
	eg.Go(func() error {
		return d.identityMgr.Run(ctx)
	})
	return eg.Wait()
}

func (d *DataBroker) update(_ context.Context, cfg *config.Config) error {
	if err := validate(cfg.Options); err != nil {
		return fmt.Errorf("databroker: bad option: %w", err)
	}

	sharedKey, err := cfg.Options.GetSharedKey()
	if err != nil {
		return fmt.Errorf("databroker: invalid shared key: %w", err)
	}
	d.sharedKey.Store(&sharedKey)

	dataBrokerClient := databrokerpb.NewDataBrokerServiceClient(d.localGRPCConnection)

	options := append([]manager.Option{
		manager.WithDataBrokerClient(dataBrokerClient),
		manager.WithEventManager(d.eventsMgr),
		manager.WithCachedGetAuthenticator(func(ctx context.Context, idpID string) (identity.Authenticator, error) {
			if !cfg.Options.SupportsUserRefresh() {
				return nil, fmt.Errorf("disabling refresh of user sessions")
			}
			return cfg.Options.GetAuthenticator(ctx, d.tracerProvider, idpID)
		}),
		manager.WithRefreshSessionAtIDTokenExpiration(manager.RefreshSessionAtIDTokenExpiration(
			cfg.Options.RuntimeFlags[config.RuntimeFlagRefreshSessionAtIDTokenExpiration])),
		manager.WithTracerProvider(d.tracerProvider),
	}, d.cfg.managerOptions...)

	if d.identityMgr == nil {
		d.identityMgr = manager.New(options...)
	} else {
		d.identityMgr.UpdateConfig(options...)
	}

	return nil
}

// validate checks that proper configuration settings are set to create
// a databroker instance
func validate(o *config.Options) error {
	sharedKey, err := o.GetSharedKey()
	if err != nil {
		return fmt.Errorf("invalid 'SHARED_SECRET': %w", err)
	}
	if _, err := cryptutil.NewAEADCipher(sharedKey); err != nil {
		return fmt.Errorf("invalid 'SHARED_SECRET': %w", err)
	}
	return nil
}

// NewServer creates a new databroker server.
func NewServer(tracerProvider oteltrace.TracerProvider, cfg *config.Config) databroker.Server {
	srv := databroker.NewBackendServer(tracerProvider)
	srv = databroker.NewClusteredServer(tracerProvider, srv, cfg)
	srv = databroker.NewSecuredServer(srv)
	return srv
}

// GetLocalDatabrokerServiceClient returns the local databroker client.
func (d *DataBroker) GetLocalDatabrokerServiceClient() databrokerpb.DataBrokerServiceClient {
	return databrokerpb.NewDataBrokerServiceClient(d.localGRPCConnection)
}
