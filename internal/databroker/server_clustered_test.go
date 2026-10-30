package databroker_test

import (
	"context"
	"net"
	"slices"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/volatiletech/null/v9"
	"go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/grpc"
	channelzpb "google.golang.org/grpc/channelz/grpc_channelz_v1"
	channelzservice "google.golang.org/grpc/channelz/service"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/databroker"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpcutil"
)

func init() {
	// FIXME: remove once the follower owns its leader connection and closes it in Stop.
	grpcutil.DefaultClientManagerIdleTimeout = time.Millisecond
}

type clusteredServerTestBackend struct {
	databroker.Server
	serverInfo func(context.Context, *emptypb.Empty) (*databrokerpb.ServerInfoResponse, error)
}

func (b clusteredServerTestBackend) OnConfigChange(_ context.Context, _ *config.Config) {
}

func (b clusteredServerTestBackend) ServerInfo(ctx context.Context, req *emptypb.Empty) (*databrokerpb.ServerInfoResponse, error) {
	return b.serverInfo(ctx, req)
}

func (b clusteredServerTestBackend) Stop() {
}

func TestClusteredServer(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cfg := config.New(config.NewDefaultOptions())
		cfg.Options.DataBroker.ClusterNodeID = null.StringFrom("node-1")

		serverInfoStarted := make(chan struct{})
		serverInfoFinished := make(chan struct{})
		configChanged := make(chan struct{})

		local := &clusteredServerTestBackend{
			serverInfo: func(ctx context.Context, _ *emptypb.Empty) (*databrokerpb.ServerInfoResponse, error) {
				close(serverInfoStarted)
				<-ctx.Done()
				// keep running after cancellation, so the server change
				// has to wait for this call to finish
				time.Sleep(time.Second)
				close(serverInfoFinished)
				return &databrokerpb.ServerInfoResponse{}, nil
			},
		}
		clustered := databroker.NewClusteredServer(noop.NewTracerProvider(), local, cfg)
		defer clustered.Stop()

		go func() {
			defer close(configChanged)
			<-serverInfoStarted
			// change the config to force an update, this should cancel the context passed to server info
			cfg.Options.DataBroker.ClusterNodeID = null.StringFrom("node-2")
			clustered.OnConfigChange(t.Context(), cfg)

			// the update should not complete until in-flight calls have finished
			select {
			case <-serverInfoFinished:
			default:
				assert.Fail(t, "config change completed before in-flight server info finished")
			}
		}()

		res, err := clustered.ServerInfo(t.Context(), new(emptypb.Empty))
		assert.NoError(t, err)
		assert.NotNil(t, res)
		<-configChanged
	})
}

func TestClusteredServerLeaderConnections(t *testing.T) {
	t.Parallel()

	t.Run("leader_change", func(t *testing.T) {
		t.Parallel()
		c := newTestCluster(t)
		c.waitClientConns(c.a, 1)

		c.setLeader("b")
		c.waitClientConns(c.a, 0)
		c.waitClientConns(c.b, 1)
	})

	t.Run("flap", func(t *testing.T) {
		t.Parallel()
		c := newTestCluster(t)
		c.waitClientConns(c.a, 1)

		for range 10 {
			c.setLeader("b")
			c.waitClientConns(c.a, 0)
			c.waitClientConns(c.b, 1)

			c.setLeader("a")
			c.waitClientConns(c.b, 0)
			c.waitClientConns(c.a, 1)
		}
	})

	t.Run("self", func(t *testing.T) {
		t.Parallel()
		c := newTestCluster(t)
		c.waitClientConns(c.a, 1)

		c.setLeader("self")
		c.waitClientConns(c.a, 0)
	})

	t.Run("disabled", func(t *testing.T) {
		t.Parallel()
		c := newTestCluster(t)
		c.waitClientConns(c.a, 1)

		c.disableClustering()
		c.waitClientConns(c.a, 0)
	})

	t.Run("stop", func(t *testing.T) {
		t.Parallel()
		c := newTestCluster(t)
		c.waitClientConns(c.a, 1)

		c.srv.Stop()
		c.waitClientConns(c.a, 0)
	})

	t.Run("unchanged", func(t *testing.T) {
		t.Parallel()
		c := newTestCluster(t)
		before := c.waitClientConns(c.a, 1)

		c.apply(c.cfg.Clone())
		assert.Equal(t, before, clientConnIDs(t, c.a))
	})

	t.Run("shared_key", func(t *testing.T) {
		t.Parallel()
		c := newTestCluster(t)
		before := c.waitClientConns(c.a, 1)

		c.rotateSharedKey()
		// FIXME: once a shared key change rebuilds the follower synchronously, check clientConnIDs directly.
		after := c.waitClientConns(c.a, 1, before...)
		assert.NotEqual(t, before, after)
	})
}

type testCluster struct {
	t    *testing.T
	a, b string
	cfg  *config.Config
	srv  databroker.Server
}

func newTestCluster(t *testing.T) *testCluster {
	t.Helper()

	c := &testCluster{t: t, a: listenAddr(t), b: listenAddr(t)}
	c.cfg = &config.Config{Options: config.NewDefaultOptions()}
	c.cfg.Options.SharedKey = cryptutil.NewBase64Key()
	c.cfg.Options.DataBroker.ClusterNodeID = null.StringFrom("self")
	c.cfg.Options.DataBroker.ClusterLeaderID = null.StringFrom("a")
	c.cfg.Options.DataBroker.ClusterNodes = config.DataBrokerClusterNodes{
		{ID: "self", GRPCAddress: "http://127.0.0.1:1"},
		{ID: "a", GRPCAddress: "http://" + c.a},
		{ID: "b", GRPCAddress: "http://" + c.b},
	}

	c.srv = databroker.NewClusteredServer(noop.NewTracerProvider(), databroker.NewBackendServer(noop.NewTracerProvider()), c.cfg)
	t.Cleanup(c.srv.Stop)
	return c
}

func (c *testCluster) apply(cfg *config.Config) {
	c.cfg = cfg
	c.srv.OnConfigChange(c.t.Context(), cfg)
}

func (c *testCluster) setLeader(id string) {
	cfg := c.cfg.Clone()
	cfg.Options.DataBroker.ClusterLeaderID = null.StringFrom(id)
	c.apply(cfg)
}

func (c *testCluster) disableClustering() {
	cfg := c.cfg.Clone()
	cfg.Options.DataBroker.ClusterNodeID = null.String{}
	cfg.Options.DataBroker.ClusterLeaderID = null.String{}
	cfg.Options.DataBroker.ClusterNodes = nil
	c.apply(cfg)
}

func (c *testCluster) rotateSharedKey() {
	cfg := c.cfg.Clone()
	cfg.Options.SharedKey = cryptutil.NewBase64Key()
	c.apply(cfg)
}

// FIXME: the client manager dials on the follower's first RPC and closes on an
// idle timer, so counts settle asynchronously. Once the follower owns its
// connection, replace this with a direct clientConnIDs check.
func (c *testCluster) waitClientConns(addr string, n int, exclude ...int64) []int64 {
	c.t.Helper()

	var ids []int64
	require.Eventually(c.t, func() bool {
		ids = clientConnIDs(c.t, addr)
		for _, id := range exclude {
			if slices.Contains(ids, id) {
				return false
			}
		}
		return len(ids) == n
	}, 5*time.Second, time.Millisecond, "expected %d client connections to %s", n, addr)
	return ids
}

func listenAddr(t *testing.T) string {
	t.Helper()

	li, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = li.Close() })
	return li.Addr().String()
}

func clientConnIDs(t *testing.T, addr string) []int64 {
	t.Helper()

	var ids []int64
	var start int64
	for {
		res, err := channelzServer.GetTopChannels(t.Context(), &channelzpb.GetTopChannelsRequest{StartChannelId: start})
		require.NoError(t, err)
		for _, ch := range res.GetChannel() {
			if ch.GetRef().GetName() == addr {
				ids = append(ids, ch.GetRef().GetChannelId())
			}
			start = ch.GetRef().GetChannelId() + 1
		}
		if res.GetEnd() {
			return ids
		}
	}
}

var channelzServer = func() channelzpb.ChannelzServer {
	r := new(capturingRegistrar)
	channelzservice.RegisterChannelzServiceToServer(r)
	return r.impl.(channelzpb.ChannelzServer)
}()

type capturingRegistrar struct {
	impl any
}

func (r *capturingRegistrar) RegisterService(_ *grpc.ServiceDesc, impl any) {
	r.impl = impl
}
