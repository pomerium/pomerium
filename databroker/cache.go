// Package databroker is a pomerium service that handles the storage of user
// session state. It communicates over RPC with other pomerium services,
// and can be configured to use a number of different backend databroker stores.
package databroker

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/rs/zerolog"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/atomicutil"
	"github.com/pomerium/pomerium/internal/events"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/version"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	"github.com/pomerium/pomerium/pkg/envoy/files"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/registry"
	"github.com/pomerium/pomerium/pkg/grpcutil"
	"github.com/pomerium/pomerium/pkg/identity"
	"github.com/pomerium/pomerium/pkg/identity/legacymanager"
	"github.com/pomerium/pomerium/pkg/identity/manager"
	"github.com/pomerium/pomerium/pkg/telemetry/trace"
	oteltrace "go.opentelemetry.io/otel/trace"
)

// DataBroker represents the databroker service. The databroker service is a simple interface
// for storing keyed blobs (bytes) of unstructured data.
type DataBroker struct {
	Options
	dataBrokerServer *dataBrokerServer
	manager          *manager.Manager
	legacyManager    *legacymanager.Manager
	eventsMgr        *events.Manager

	localListener       net.Listener
	localGRPCServer     *grpc.Server
	localGRPCConnection *grpc.ClientConn
	sharedKey           *atomicutil.Value[[]byte]
	tracerProvider      oteltrace.TracerProvider
	tracer              oteltrace.Tracer
}

type Options struct {
	managerOptions       []manager.Option
	legacyManagerOptions []legacymanager.Option
}

type Option func(*Options)

func (o *Options) apply(opts ...Option) {
	for _, op := range opts {
		op(o)
	}
}

func WithManagerOptions(managerOptions ...manager.Option) Option {
	return func(o *Options) {
		o.managerOptions = append(o.managerOptions, managerOptions...)
	}
}

func WithLegacyManagerOptions(legacyManagerOptions ...legacymanager.Option) Option {
	return func(o *Options) {
		o.legacyManagerOptions = append(o.legacyManagerOptions, legacyManagerOptions...)
	}
}

// New creates a new databroker service.
func New(ctx context.Context, cfg *config.Config, eventsMgr *events.Manager, opts ...Option) (*DataBroker, error) {
	options := Options{}
	options.apply(opts...)

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

	sharedKey, err := cfg.Options.GetSharedKey()
	if err != nil {
		return nil, err
	}

	sharedKeyValue := atomicutil.NewValue(sharedKey)
	clientDialOptions := []grpc.DialOption{
		grpc.WithInsecure(),
		grpc.WithChainUnaryInterceptor(grpcutil.WithUnarySignedJWT(sharedKeyValue.Load)),
		grpc.WithChainStreamInterceptor(grpcutil.WithStreamSignedJWT(sharedKeyValue.Load)),
		grpc.WithStatsHandler(otelgrpc.NewClientHandler(otelgrpc.WithTracerProvider(tracerProvider))),
	}

	ctx = log.WithContext(ctx, func(c zerolog.Context) zerolog.Context {
		return c.Str("service", "databroker").Str("config_source", "bootstrap")
	})
	localGRPCConnection, err := grpc.DialContext(
		ctx,
		localListener.Addr().String(),
		clientDialOptions...,
	)
	if err != nil {
		return nil, err
	}

	dataBrokerServer, err := newDataBrokerServer(ctx, tracerProvider, cfg)
	if err != nil {
		return nil, err
	}

	c := &DataBroker{
		Options:             options,
		dataBrokerServer:    dataBrokerServer,
		localListener:       localListener,
		localGRPCServer:     localGRPCServer,
		localGRPCConnection: localGRPCConnection,
		sharedKey:           sharedKeyValue,
		eventsMgr:           eventsMgr,
		tracerProvider:      tracerProvider,
		tracer:              tracer,
	}
	c.Register(c.localGRPCServer)

	err = c.update(ctx, cfg)
	if err != nil {
		return nil, err
	}

	return c, nil
}

// OnConfigChange is called whenever configuration is changed.
func (c *DataBroker) OnConfigChange(ctx context.Context, cfg *config.Config) {
	err := c.update(ctx, cfg)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("databroker: error updating configuration")
	}

	c.dataBrokerServer.OnConfigChange(ctx, cfg)
}

// Register registers all the gRPC services with the given server.
func (c *DataBroker) Register(grpcServer *grpc.Server) {
	databroker.RegisterDataBrokerServiceServer(grpcServer, c.dataBrokerServer)
	registry.RegisterRegistryServer(grpcServer, c.dataBrokerServer)
}

// Run runs the databroker components.
func (c *DataBroker) Run(ctx context.Context) error {
	eg, ctx := errgroup.WithContext(ctx)
	eg.Go(func() error {
		return grpcutil.ServeWithGracefulStop(ctx, c.localGRPCServer, c.localListener, time.Second*5)
	})
	eg.Go(func() error {
		return c.manager.Run(ctx)
	})
	return eg.Wait()
}

func (c *DataBroker) update(ctx context.Context, cfg *config.Config) error {
	if err := validate(cfg.Options); err != nil {
		return fmt.Errorf("databroker: bad option: %w", err)
	}

	sharedKey, err := cfg.Options.GetSharedKey()
	if err != nil {
		return fmt.Errorf("databroker: invalid shared key: %w", err)
	}
	c.sharedKey.Store(sharedKey)

	oauthOptions, err := cfg.Options.GetOauthOptions()
	if err != nil {
		return fmt.Errorf("databroker: invalid oauth options: %w", err)
	}

	dataBrokerClient := databroker.NewDataBrokerServiceClient(c.localGRPCConnection)

	options := append([]manager.Option{
		manager.WithDataBrokerClient(dataBrokerClient),
		manager.WithEventManager(c.eventsMgr),
		manager.WithEnabled(!cfg.Options.IsRuntimeFlagSet(config.RuntimeFlagLegacyIdentityManager)),
	}, c.managerOptions...)
	legacyOptions := append([]legacymanager.Option{
		legacymanager.WithDataBrokerClient(dataBrokerClient),
		legacymanager.WithEventManager(c.eventsMgr),
		legacymanager.WithEnabled(cfg.Options.IsRuntimeFlagSet(config.RuntimeFlagLegacyIdentityManager)),
	}, c.legacyManagerOptions...)

	if cfg.Options.SupportsUserRefresh() {
		authenticator, err := identity.NewAuthenticator(ctx, c.tracerProvider, oauthOptions)
		if err != nil {
			log.Ctx(ctx).Error().Err(err).Msg("databroker: failed to create authenticator")
		} else {
			options = append(options, manager.WithAuthenticator(authenticator))
			legacyOptions = append(legacyOptions, legacymanager.WithAuthenticator(authenticator))
		}
	} else {
		log.Ctx(ctx).Info().Msg("databroker: disabling refresh of user sessions")
	}

	if c.manager == nil {
		c.manager = manager.New(options...)
	} else {
		c.manager.UpdateConfig(options...)
	}

	if c.legacyManager == nil {
		c.legacyManager = legacymanager.New(legacyOptions...)
	} else {
		c.legacyManager.UpdateConfig(legacyOptions...)
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
