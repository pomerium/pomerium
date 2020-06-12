// Package cache is a pomerium service that handles the storage of user
// session state. It communicates over RPC with other pomerium services,
// and can be configured to use a number of different backend cache stores.
package cache

import (
	"context"
	"errors"
	"fmt"
	stdlog "log"
	"net"

	"google.golang.org/grpc"
	"gopkg.in/tomb.v2"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/cryptutil"
	"github.com/pomerium/pomerium/internal/directory"
	pbCache "github.com/pomerium/pomerium/internal/grpc/cache"
	"github.com/pomerium/pomerium/internal/grpc/databroker"
	"github.com/pomerium/pomerium/internal/grpc/session"
	"github.com/pomerium/pomerium/internal/grpc/user"
	"github.com/pomerium/pomerium/internal/identity"
	"github.com/pomerium/pomerium/internal/identity/manager"
	"github.com/pomerium/pomerium/internal/kv"
	"github.com/pomerium/pomerium/internal/kv/autocache"
	"github.com/pomerium/pomerium/internal/kv/bolt"
	"github.com/pomerium/pomerium/internal/kv/redis"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/urlutil"
)

// Cache represents the cache service. The cache service is a simple interface
// for storing keyed blobs (bytes) of unstructured data.
type Cache struct {
	cache            kv.Store
	dataBrokerServer *DataBrokerServer
	sessionServer    *SessionServer
	userServer       *UserServer
	manager          *manager.Manager

	localListener       net.Listener
	localGRPCServer     *grpc.Server
	localGRPCConnection *grpc.ClientConn
}

// New creates a new cache service.
func New(opts config.Options) (*Cache, error) {
	if err := validate(opts); err != nil {
		return nil, fmt.Errorf("cache: bad option: %w", err)
	}

	cache, err := newCacheStore(opts.CacheStore, &opts)
	if err != nil {
		return nil, err
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
	localGRPCServer := grpc.NewServer()
	localGRPCConnection, err := grpc.DialContext(context.Background(), localListener.Addr().String(),
		grpc.WithInsecure())
	if err != nil {
		return nil, err
	}

	dataBrokerServer := NewDataBrokerServer(localGRPCServer)
	dataBrokerClient := databroker.NewDataBrokerServiceClient(localGRPCConnection)
	sessionServer := NewSessionServer(localGRPCServer, dataBrokerClient)
	sessionClient := session.NewSessionServiceClient(localGRPCConnection)
	userServer := NewUserServer(localGRPCServer, dataBrokerClient)
	userClient := user.NewUserServiceClient(localGRPCConnection)

	manager := manager.New(authenticator, directoryProvider, sessionClient, userClient, dataBrokerClient)

	return &Cache{
		cache:            cache,
		dataBrokerServer: dataBrokerServer,
		sessionServer:    sessionServer,
		userServer:       userServer,
		manager:          manager,

		localListener:       localListener,
		localGRPCServer:     localGRPCServer,
		localGRPCConnection: localGRPCConnection,
	}, nil
}

// Register registers all the gRPC services with the given server.
func (c *Cache) Register(grpcServer *grpc.Server) {
	pbCache.RegisterCacheServer(grpcServer, c)
	databroker.RegisterDataBrokerServiceServer(grpcServer, c.dataBrokerServer)
	session.RegisterSessionServiceServer(grpcServer, c.sessionServer)
	user.RegisterUserServiceServer(grpcServer, c.userServer)
}

// Run runs the cache components.
func (c *Cache) Run(ctx context.Context) error {
	t, ctx := tomb.WithContext(ctx)
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
	if err := urlutil.ValidateURL(o.CacheURL); err != nil {
		return fmt.Errorf("invalid 'CACHE_SERVICE_URL': %w", err)
	}
	return nil
}

// newCacheStore creates a new cache store by name and given a set of
// configuration options.
func newCacheStore(name string, o *config.Options) (s kv.Store, err error) {
	switch name {
	case bolt.Name:
		s, err = bolt.New(&bolt.Options{Path: o.CacheStorePath})
	case redis.Name:
		s, err = redis.New(&redis.Options{
			Addr:     o.CacheStoreAddr,
			Password: o.CacheStorePassword,
		})
	case autocache.Name:
		acLog := log.Logger.With().Str("service", autocache.Name).Logger()
		s, err = autocache.New(&autocache.Options{
			SharedKey:     o.SharedKey,
			Log:           stdlog.New(acLog, "", 0),
			ClusterDomain: o.GetCacheURL().Hostname(),
		})
	default:
		return nil, fmt.Errorf("cache: unknown store: %s", name)
	}
	if err != nil {
		return nil, err
	}
	return s, nil
}

// Close shuts down the underlying cache store, services, or both -- if any.
func (c *Cache) Close() error {
	if c.cache == nil {
		return errors.New("cache: cannot close nil cache")
	}
	return c.cache.Close(context.TODO())
}
