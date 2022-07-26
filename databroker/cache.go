// Package databroker is a pomerium service that handles the storage of user
// session state. It communicates over RPC with other pomerium services,
// and can be configured to use a number of different backend databroker stores.
package databroker

import (
	"context"
	"fmt"
	"net"
	"sync"

	"github.com/rs/zerolog"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/atomicutil"
	"github.com/pomerium/pomerium/internal/directory"
	"github.com/pomerium/pomerium/internal/events"
	"github.com/pomerium/pomerium/internal/identity"
	"github.com/pomerium/pomerium/internal/identity/manager"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/telemetry"
	"github.com/pomerium/pomerium/internal/version"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	"github.com/pomerium/pomerium/pkg/envoy/files"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/registry"
	"github.com/pomerium/pomerium/pkg/grpcutil"
)

// DataBroker represents the databroker service. The databroker service is a simple interface
// for storing keyed blobs (bytes) of unstructured data.
type DataBroker struct {
	dataBrokerServer *dataBrokerServer
	manager          *manager.Manager
	eventsMgr        *events.Manager

	localListener       net.Listener
	localGRPCServer     *grpc.Server
	localGRPCConnection *grpc.ClientConn
	sharedKey           *atomicutil.Value[[]byte]

	mu                sync.Mutex
	directoryProvider directory.Provider
}

// New creates a new databroker service.
func New(cfg *config.Config, eventsMgr *events.Manager) (*DataBroker, error) {
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

	// No metrics handler because we have one in the control plane.  Add one
	// if we no longer register with that grpc Server
	localGRPCServer := grpc.NewServer(
		grpc.StreamInterceptor(si),
		grpc.UnaryInterceptor(ui),
	)

	sharedKey, err := cfg.Options.GetSharedKey()
	if err != nil {
		return nil, err
	}

	sharedKeyValue := atomicutil.NewValue(sharedKey)
	clientStatsHandler := telemetry.NewGRPCClientStatsHandler(cfg.Options.Services)
	clientDialOptions := []grpc.DialOption{
		grpc.WithInsecure(),
		grpc.WithChainUnaryInterceptor(clientStatsHandler.UnaryInterceptor, grpcutil.WithUnarySignedJWT(sharedKeyValue.Load)),
		grpc.WithChainStreamInterceptor(grpcutil.WithStreamSignedJWT(sharedKeyValue.Load)),
		grpc.WithStatsHandler(clientStatsHandler.Handler),
	}

	ctx := log.WithContext(context.Background(), func(c zerolog.Context) zerolog.Context {
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

	dataBrokerServer := newDataBrokerServer(cfg)

	c := &DataBroker{
		dataBrokerServer:    dataBrokerServer,
		localListener:       localListener,
		localGRPCServer:     localGRPCServer,
		localGRPCConnection: localGRPCConnection,
		sharedKey:           sharedKeyValue,
		eventsMgr:           eventsMgr,
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
		log.Error(ctx).Err(err).Msg("databroker: error updating configuration")
	}

	c.dataBrokerServer.OnConfigChange(ctx, cfg)
}

// Register registers all the gRPC services with the given server.
func (c *DataBroker) Register(grpcServer *grpc.Server) {
	databroker.RegisterDataBrokerServiceServer(grpcServer, c.dataBrokerServer)
	directory.RegisterDirectoryServiceServer(grpcServer, c)
	registry.RegisterRegistryServer(grpcServer, c.dataBrokerServer)
}

// Run runs the databroker components.
func (c *DataBroker) Run(ctx context.Context) error {
	eg, ctx := errgroup.WithContext(ctx)
	eg.Go(func() error {
		return c.localGRPCServer.Serve(c.localListener)
	})
	eg.Go(func() error {
		<-ctx.Done()
		c.localGRPCServer.Stop()
		return nil
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

	clientSecret, err := cfg.Options.GetClientSecret()
	if err != nil {
		return fmt.Errorf("databroker: error retrieving IPD client secret: %w", err)
	}

	directoryProvider := directory.GetProvider(directory.Options{
		ServiceAccount: cfg.Options.ServiceAccount,
		Provider:       cfg.Options.Provider,
		ProviderURL:    cfg.Options.ProviderURL,
		QPS:            cfg.Options.GetQPS(),
		ClientID:       cfg.Options.ClientID,
		ClientSecret:   clientSecret,
	})
	c.mu.Lock()
	c.directoryProvider = directoryProvider
	c.mu.Unlock()

	dataBrokerClient := databroker.NewDataBrokerServiceClient(c.localGRPCConnection)

	options := []manager.Option{
		manager.WithDirectoryProvider(directoryProvider),
		manager.WithDataBrokerClient(dataBrokerClient),
		manager.WithGroupRefreshInterval(cfg.Options.RefreshDirectoryInterval),
		manager.WithGroupRefreshTimeout(cfg.Options.RefreshDirectoryTimeout),
		manager.WithEventManager(c.eventsMgr),
	}

	authenticator, err := identity.NewAuthenticator(oauthOptions)
	if err != nil {
		log.Error(ctx).Err(err).Msg("databroker: failed to create authenticator")
	} else {
		options = append(options, manager.WithAuthenticator(authenticator))
	}

	if c.manager == nil {
		c.manager = manager.New(options...)
	} else {
		c.manager.UpdateConfig(options...)
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
