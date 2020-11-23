// Package cache is a pomerium service that handles the storage of user
// session state. It communicates over RPC with other pomerium services,
// and can be configured to use a number of different backend cache stores.
package cache

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"sync"

	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/directory"
	"github.com/pomerium/pomerium/internal/identity"
	"github.com/pomerium/pomerium/internal/identity/manager"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/telemetry"
	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/internal/version"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpcutil"
)

// Cache represents the cache service. The cache service is a simple interface
// for storing keyed blobs (bytes) of unstructured data.
type Cache struct {
	dataBrokerServer *dataBrokerServer
	manager          *manager.Manager

	localListener                net.Listener
	localGRPCServer              *grpc.Server
	localGRPCConnection          *grpc.ClientConn
	dataBrokerStorageType        string //TODO remove in v0.11
	deprecatedCacheClusterDomain string //TODO: remove in v0.11

	mu                sync.Mutex
	directoryProvider directory.Provider
}

// New creates a new cache service.
func New(cfg *config.Config) (*Cache, error) {
	localListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}

	sharedKey, _ := base64.StdEncoding.DecodeString(cfg.Options.SharedKey)

	ui, si := grpcutil.AttachMetadataInterceptors(
		metadata.Pairs(grpcutil.MetadataKeyPomeriumVersion, version.FullVersion()),
	)

	// No metrics handler because we have one in the control plane.  Add one
	// if we no longer register with that grpc Server
	localGRPCServer := grpc.NewServer(
		grpc.StreamInterceptor(si),
		grpc.UnaryInterceptor(ui),
	)

	clientStatsHandler := telemetry.NewGRPCClientStatsHandler(cfg.Options.Services)
	clientDialOptions := []grpc.DialOption{
		grpc.WithInsecure(),
		grpc.WithChainUnaryInterceptor(clientStatsHandler.UnaryInterceptor, grpcutil.WithUnarySignedJWT(sharedKey)),
		grpc.WithChainStreamInterceptor(grpcutil.WithStreamSignedJWT(sharedKey)),
		grpc.WithStatsHandler(clientStatsHandler.Handler),
	}

	localGRPCConnection, err := grpc.DialContext(
		context.Background(),
		localListener.Addr().String(),
		clientDialOptions...,
	)
	if err != nil {
		return nil, err
	}

	dataBrokerServer := newDataBrokerServer(cfg)

	c := &Cache{
		dataBrokerServer:             dataBrokerServer,
		localListener:                localListener,
		localGRPCServer:              localGRPCServer,
		localGRPCConnection:          localGRPCConnection,
		deprecatedCacheClusterDomain: cfg.Options.GetDataBrokerURL().Hostname(),
		dataBrokerStorageType:        cfg.Options.DataBrokerStorageType,
	}
	c.Register(c.localGRPCServer)

	err = c.update(cfg)
	if err != nil {
		return nil, err
	}

	return c, nil
}

// OnConfigChange is called whenever configuration is changed.
func (c *Cache) OnConfigChange(cfg *config.Config) {
	err := c.update(cfg)
	if err != nil {
		log.Error().Err(err).Msg("cache: error updating configuration")
	}

	c.dataBrokerServer.OnConfigChange(cfg)
}

// Register registers all the gRPC services with the given server.
func (c *Cache) Register(grpcServer *grpc.Server) {
	databroker.RegisterDataBrokerServiceServer(grpcServer, c.dataBrokerServer)
	directory.RegisterDirectoryServiceServer(grpcServer, c)
}

// Run runs the cache components.
func (c *Cache) Run(ctx context.Context) error {
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

func (c *Cache) update(cfg *config.Config) error {
	if err := validate(cfg.Options); err != nil {
		return fmt.Errorf("cache: bad option: %w", err)
	}

	authenticator, err := identity.NewAuthenticator(cfg.Options.GetOauthOptions())
	if err != nil {
		return fmt.Errorf("cache: failed to create authenticator: %w", err)
	}

	directoryProvider := directory.GetProvider(directory.Options{
		ServiceAccount: cfg.Options.ServiceAccount,
		Provider:       cfg.Options.Provider,
		ProviderURL:    cfg.Options.ProviderURL,
		QPS:            cfg.Options.QPS,
		ClientID:       cfg.Options.ClientID,
		ClientSecret:   cfg.Options.ClientSecret,
	})
	c.mu.Lock()
	c.directoryProvider = directoryProvider
	c.mu.Unlock()

	dataBrokerClient := databroker.NewDataBrokerServiceClient(c.localGRPCConnection)

	options := []manager.Option{
		manager.WithAuthenticator(authenticator),
		manager.WithDirectoryProvider(directoryProvider),
		manager.WithDataBrokerClient(dataBrokerClient),
		manager.WithGroupRefreshInterval(cfg.Options.RefreshDirectoryInterval),
		manager.WithGroupRefreshTimeout(cfg.Options.RefreshDirectoryTimeout),
	}

	if c.manager == nil {
		c.manager = manager.New(options...)
	} else {
		c.manager.UpdateConfig(options...)
	}

	return nil
}

// validate checks that proper configuration settings are set to create
// a cache instance
func validate(o *config.Options) error {
	if _, err := cryptutil.NewAEADCipherFromBase64(o.SharedKey); err != nil {
		return fmt.Errorf("invalid 'SHARED_SECRET': %w", err)
	}
	if err := urlutil.ValidateURL(o.DataBrokerURL); err != nil {
		return fmt.Errorf("invalid 'DATA_BROKER_SERVICE_URL': %w", err)
	}
	return nil
}
