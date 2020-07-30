// Package cache is a pomerium service that handles the storage of user
// session state. It communicates over RPC with other pomerium services,
// and can be configured to use a number of different backend cache stores.
package cache

import (
	"context"
	"fmt"
	"net"

	"google.golang.org/grpc"
	"gopkg.in/tomb.v2"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/directory"
	"github.com/pomerium/pomerium/internal/identity"
	"github.com/pomerium/pomerium/internal/identity/manager"
	"github.com/pomerium/pomerium/internal/telemetry"
	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
)

// Cache represents the cache service. The cache service is a simple interface
// for storing keyed blobs (bytes) of unstructured data.
type Cache struct {
	dataBrokerServer *DataBrokerServer
	manager          *manager.Manager

	localListener                net.Listener
	localGRPCServer              *grpc.Server
	localGRPCConnection          *grpc.ClientConn
	deprecatedCacheClusterDomain string //TODO: remove in v0.11
}

// New creates a new cache service.
func New(opts config.Options) (*Cache, error) {
	if err := validate(opts); err != nil {
		return nil, fmt.Errorf("cache: bad option: %w", err)
	}

	authenticator, err := identity.NewAuthenticator(opts.GetOauthOptions())
	if err != nil {
		return nil, fmt.Errorf("cache: failed to create authenticator: %w", err)
	}

	directoryProvider := directory.GetProvider(&opts)

	localListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}

	// No metrics handler because we have one in the control plane.  Add one
	// if we no longer register with that grpc Server
	localGRPCServer := grpc.NewServer()

	clientStatsHandler := telemetry.NewGRPCClientStatsHandler(opts.Services)
	clientDialOptions := clientStatsHandler.DialOptions(grpc.WithInsecure())

	localGRPCConnection, err := grpc.DialContext(
		context.Background(),
		localListener.Addr().String(),
		clientDialOptions...,
	)
	if err != nil {
		return nil, err
	}

	dataBrokerServer, err := NewDataBrokerServer(localGRPCServer, opts)
	if err != nil {
		return nil, err
	}
	dataBrokerClient := databroker.NewDataBrokerServiceClient(localGRPCConnection)

	manager := manager.New(
		authenticator,
		directoryProvider,
		dataBrokerClient,
		manager.WithGroupRefreshInterval(opts.RefreshDirectoryInterval),
		manager.WithGroupRefreshTimeout(opts.RefreshDirectoryTimeout),
	)

	return &Cache{
		dataBrokerServer: dataBrokerServer,
		manager:          manager,

		localListener:                localListener,
		localGRPCServer:              localGRPCServer,
		localGRPCConnection:          localGRPCConnection,
		deprecatedCacheClusterDomain: opts.GetDataBrokerURL().Hostname(),
	}, nil
}

// Register registers all the gRPC services with the given server.
func (c *Cache) Register(grpcServer *grpc.Server) {
	databroker.RegisterDataBrokerServiceServer(grpcServer, c.dataBrokerServer)
}

// Run runs the cache components.
func (c *Cache) Run(ctx context.Context) error {
	t, ctx := tomb.WithContext(ctx)
	t.Go(func() error {
		return c.runMemberList(ctx)
	})
	t.Go(func() error {
		return c.localGRPCServer.Serve(c.localListener)
	})
	t.Go(func() error {
		<-ctx.Done()
		c.localGRPCServer.Stop()
		return nil
	})
	t.Go(func() error {
		return c.manager.Run(ctx)
	})
	return t.Wait()
}

// validate checks that proper configuration settings are set to create
// a cache instance
func validate(o config.Options) error {
	if _, err := cryptutil.NewAEADCipherFromBase64(o.SharedKey); err != nil {
		return fmt.Errorf("invalid 'SHARED_SECRET': %w", err)
	}
	if err := urlutil.ValidateURL(o.DataBrokerURL); err != nil {
		return fmt.Errorf("invalid 'DATA_BROKER_SERVICE_URL': %w", err)
	}
	return nil
}
