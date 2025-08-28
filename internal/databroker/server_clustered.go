package databroker

import (
	"context"
	"sync"
	"time"

	oteltrace "go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/databroker/cluster"
	"github.com/pomerium/pomerium/internal/log"
	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
	registrypb "github.com/pomerium/pomerium/pkg/grpc/registry"
)

type clusteredServer struct {
	local                    Server
	clientManager            *ClientManager
	dataBrokerTopologySource cluster.DataBrokerTopologySource
	leaderTopologySource     cluster.TopologySource

	mu       sync.Mutex
	leader   Server
	leaderID uint64
}

func NewClusteredServer(tracerProvider oteltrace.TracerProvider, local Server, cfg *config.Config) Server {
	srv := &clusteredServer{
		local:         local,
		clientManager: NewClientManager(tracerProvider),
	}
	srv.dataBrokerTopologySource = cluster.NewDataBrokerTopologySource(tracerProvider, srv.clientManager)
	srv.leaderTopologySource = cluster.NewLowestNodeIDLeaderElectorTopologySource(srv.dataBrokerTopologySource)
	srv.updateTopologySourceLocked(cfg)
	return srv
}

func (srv *clusteredServer) AcquireLease(ctx context.Context, req *databrokerpb.AcquireLeaseRequest) (res *databrokerpb.AcquireLeaseResponse, err error) {
	err = srv.withReadWriteNode(ctx, func(ctx context.Context, s Server) error {
		var err error
		res, err = s.AcquireLease(ctx, req)
		return err
	})
	if err != nil {
		return nil, err
	}
	return res, err
}

func (srv *clusteredServer) Get(ctx context.Context, req *databrokerpb.GetRequest) (res *databrokerpb.GetResponse, err error) {
	err = srv.withReadOnlyNode(ctx, func(ctx context.Context, s Server) error {
		var err error
		res, err = s.Get(ctx, req)
		return err
	})
	if err != nil {
		return nil, err
	}
	return res, err
}

func (srv *clusteredServer) List(ctx context.Context, req *registrypb.ListRequest) (res *registrypb.ServiceList, err error) {
	err = srv.withReadOnlyNode(ctx, func(ctx context.Context, s Server) error {
		var err error
		res, err = s.List(ctx, req)
		return err
	})
	if err != nil {
		return nil, err
	}
	return res, err
}

func (srv *clusteredServer) ListTypes(ctx context.Context, req *emptypb.Empty) (res *databrokerpb.ListTypesResponse, err error) {
	err = srv.withReadOnlyNode(ctx, func(ctx context.Context, s Server) error {
		var err error
		res, err = s.ListTypes(ctx, req)
		return err
	})
	if err != nil {
		return nil, err
	}
	return res, err
}

func (srv *clusteredServer) Patch(ctx context.Context, req *databrokerpb.PatchRequest) (res *databrokerpb.PatchResponse, err error) {
	err = srv.withReadWriteNode(ctx, func(ctx context.Context, s Server) error {
		var err error
		res, err = s.Patch(ctx, req)
		return err
	})
	if err != nil {
		return nil, err
	}
	return res, err
}

func (srv *clusteredServer) Put(ctx context.Context, req *databrokerpb.PutRequest) (res *databrokerpb.PutResponse, err error) {
	err = srv.withReadWriteNode(ctx, func(ctx context.Context, s Server) error {
		var err error
		res, err = s.Put(ctx, req)
		return err
	})
	if err != nil {
		return nil, err
	}
	return res, err
}

func (srv *clusteredServer) Query(ctx context.Context, req *databrokerpb.QueryRequest) (res *databrokerpb.QueryResponse, err error) {
	err = srv.withReadOnlyNode(ctx, func(ctx context.Context, s Server) error {
		var err error
		res, err = s.Query(ctx, req)
		return err
	})
	if err != nil {
		return nil, err
	}
	return res, err
}

func (srv *clusteredServer) ReleaseLease(ctx context.Context, req *databrokerpb.ReleaseLeaseRequest) (res *emptypb.Empty, err error) {
	err = srv.withReadWriteNode(ctx, func(ctx context.Context, s Server) error {
		var err error
		res, err = s.ReleaseLease(ctx, req)
		return err
	})
	if err != nil {
		return nil, err
	}
	return res, err
}

func (srv *clusteredServer) RenewLease(ctx context.Context, req *databrokerpb.RenewLeaseRequest) (res *emptypb.Empty, err error) {
	err = srv.withReadWriteNode(ctx, func(ctx context.Context, s Server) error {
		var err error
		res, err = s.RenewLease(ctx, req)
		return err
	})
	if err != nil {
		return nil, err
	}
	return res, err
}

func (srv *clusteredServer) Report(ctx context.Context, req *registrypb.RegisterRequest) (res *registrypb.RegisterResponse, err error) {
	err = srv.withReadWriteNode(ctx, func(ctx context.Context, s Server) error {
		var err error
		res, err = s.Report(ctx, req)
		return err
	})
	if err != nil {
		return nil, err
	}
	return res, err
}

func (srv *clusteredServer) ServerInfo(ctx context.Context, req *emptypb.Empty) (res *databrokerpb.ServerInfoResponse, err error) {
	err = srv.withReadOnlyNode(ctx, func(ctx context.Context, s Server) error {
		var err error
		res, err = s.ServerInfo(ctx, req)
		return err
	})
	if err != nil {
		return nil, err
	}

	ch := srv.leaderTopologySource.Bind()
	select {
	case topology := <-ch:
		for _, n := range topology.Nodes {
			if n.NodeID == res.GetNodeId() {
				continue
			}
			res.Peers = append(res.Peers, &databrokerpb.ServerInfoResponse_Peer{
				Url:           n.URL,
				NodeId:        n.NodeID,
				ServerVersion: n.ServerVersion,
			})
		}
	default:
	}
	srv.dataBrokerTopologySource.Unbind(ch)

	return res, err
}

func (srv *clusteredServer) SetOptions(ctx context.Context, req *databrokerpb.SetOptionsRequest) (res *databrokerpb.SetOptionsResponse, err error) {
	err = srv.withReadWriteNode(ctx, func(ctx context.Context, s Server) error {
		var err error
		res, err = s.SetOptions(ctx, req)
		return err
	})
	if err != nil {
		return nil, err
	}
	return res, err
}

func (srv *clusteredServer) Sync(req *databrokerpb.SyncRequest, stream grpc.ServerStreamingServer[databrokerpb.SyncResponse]) error {
	return srv.withReadOnlyNode(stream.Context(), func(ctx context.Context, s Server) error {
		return s.Sync(req, newStreamWithContext(ctx, stream))
	})
}

func (srv *clusteredServer) SyncLatest(req *databrokerpb.SyncLatestRequest, stream grpc.ServerStreamingServer[databrokerpb.SyncLatestResponse]) error {
	return srv.withReadOnlyNode(stream.Context(), func(ctx context.Context, s Server) error {
		return s.SyncLatest(req, newStreamWithContext(ctx, stream))
	})
}

func (srv *clusteredServer) Watch(req *registrypb.ListRequest, stream grpc.ServerStreamingServer[registrypb.ServiceList]) error {
	return srv.withReadOnlyNode(stream.Context(), func(ctx context.Context, s Server) error {
		return s.Watch(req, newStreamWithContext(ctx, stream))
	})
}

func (srv *clusteredServer) Stop() {
}

func (srv *clusteredServer) OnConfigChange(ctx context.Context, cfg *config.Config) {
	srv.clientManager.OnConfigChange(ctx, cfg)

	srv.mu.Lock()
	defer srv.mu.Unlock()

	if srv.leader != nil {
		srv.leader.OnConfigChange(ctx, cfg)
	}
	srv.updateTopologySourceLocked(cfg)
}

func (srv *clusteredServer) getLeader(ctx context.Context) (Server, error) {
	ctx, clearTimeout := context.WithTimeoutCause(ctx, time.Second*3, databrokerpb.ErrClusterHasNoLeader)
	defer clearTimeout()

	ch := srv.leaderTopologySource.Bind()
	defer srv.leaderTopologySource.Unbind(ch)

	for {
		select {
		case <-ctx.Done():
			return nil, context.Cause(ctx)
		case topology := <-ch:
			for _, n := range topology.Nodes {
				if !n.IsLeader {
					continue
				}

				if n.IsLocal {
					return srv.local, nil
				}

				srv.mu.Lock()
				// stop the existing leader
				if srv.leader != nil && n.NodeID != srv.leaderID {
					srv.leader.Stop()
					srv.leader = nil
					srv.leaderID = 0
				}
				// start a new one
				if srv.leader == nil {
					srv.leader = NewForwardingServer(srv.clientManager.GetClient(n.URL))
					srv.leaderID = n.NodeID
				}
				leader := srv.leader
				srv.mu.Unlock()

				return leader, nil
			}
		}
	}
}

func (srv *clusteredServer) withReadOnlyNode(ctx context.Context, fn func(ctx context.Context, srv Server) error) error {
	mode := GetIncomingClusterRequestMode(ctx)

	// for local mode we don't have to find the leader
	if mode == ClusterRequestModeLocal {
		return fn(ctx, srv.local)
	}

	// find the leader
	leader, err := srv.getLeader(ctx)
	if err != nil {
		return err
	}

	// leader is either a forwarding server or the local server

	switch mode {
	case ClusterRequestModeDefault:
		return fn(WithOutgoingClusterRequestMode(ctx, ClusterRequestModeLeader), leader)
	case ClusterRequestModeLeader:
		// in leader mode we only allow calls if we're the leader
		if leader == srv.local {
			return fn(ctx, leader)
		}
		return databrokerpb.ErrNodeIsNotLeader
	default:
		return databrokerpb.ErrUnknownClusterRequestMode
	}
}

func (srv *clusteredServer) withReadWriteNode(ctx context.Context, fn func(ctx context.Context, srv Server) error) error {
	// find the leader
	leader, err := srv.getLeader(ctx)
	if err != nil {
		return err
	}

	// leader is either a forwarding server or the local server

	switch GetIncomingClusterRequestMode(ctx) {
	case ClusterRequestModeDefault:
		return fn(WithOutgoingClusterRequestMode(ctx, ClusterRequestModeLeader), leader)
	case ClusterRequestModeLocal, ClusterRequestModeLeader:
		// in leader and local modes we only allow calls if we're the leader
		if leader == srv.local {
			return fn(ctx, leader)
		}
		return databrokerpb.ErrNodeIsNotLeader
	default:
		return databrokerpb.ErrUnknownClusterRequestMode
	}
}

func (srv *clusteredServer) updateTopologySourceLocked(cfg *config.Config) {
	urls, err := cfg.Options.GetDataBrokerURLs()
	if err != nil {
		log.Error().Err(err).Msg("databroker-clustered-server: error retrieving databroker urls")
		return
	}
	bootstrapURLs := make([]string, len(urls))
	for i, u := range urls {
		bootstrapURLs[i] = u.String()
	}

	localInfo, err := srv.local.ServerInfo(context.Background(), new(emptypb.Empty))
	if err != nil {
		log.Error().Err(err).Msg("databroker-clustered-server: error retrieving local server info")
		return
	}

	srv.dataBrokerTopologySource.UpdateOptions(
		cluster.WithDataBrokerTopologySourceBootstrapURLs(bootstrapURLs),
		cluster.WithDataBrokerTopologySourceLocalNode(localInfo.GetNodeId(), localInfo.GetServerVersion()),
	)
}

type streamWithContext[Res any] struct {
	grpc.ServerStreamingServer[Res]
	ctx context.Context
}

func newStreamWithContext[Res any](ctx context.Context, stream grpc.ServerStreamingServer[Res]) grpc.ServerStreamingServer[Res] {
	return streamWithContext[Res]{stream, ctx}
}

func (stream streamWithContext[Res]) Context() context.Context {
	return stream.ctx
}
