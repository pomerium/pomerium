package databroker

import (
	"cmp"
	"context"
	"fmt"
	"maps"
	"slices"
	"sync"
	"time"

	"github.com/hashicorp/go-set/v3"
	"github.com/rs/zerolog"
	oteltrace "go.opentelemetry.io/otel/trace"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/telemetry"
	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
	registrypb "github.com/pomerium/pomerium/pkg/grpc/registry"
)

type node struct {
	isLeader      bool
	isLocal       bool
	url           string
	nodeID        uint64
	serverVersion uint64
}

func mergeNodes(n1, n2 node) node {
	return node{
		isLeader:      cmp.Or(n1.isLeader, n2.isLeader),
		isLocal:       cmp.Or(n1.isLocal, n2.isLocal),
		url:           cmp.Or(n1.url, n2.url),
		nodeID:        cmp.Or(n1.nodeID, n2.nodeID),
		serverVersion: cmp.Or(n1.serverVersion, n2.serverVersion),
	}
}

type clusterTopologyMapper struct {
	local     Server
	mgr       *ClientConnectionManager
	telemetry telemetry.Component

	mu        sync.Mutex
	current   []node
	listeners set.Set[chan []node]
}

func newClusterTopologyMapper(tracerProvider oteltrace.TracerProvider, local Server) *clusterTopologyMapper {
	return &clusterTopologyMapper{
		local:     local,
		mgr:       NewClientConnectionManager(),
		telemetry: *telemetry.NewComponent(tracerProvider, zerolog.InfoLevel, "databroker/cluster-topology-mapper"),
	}
}

func (mapper *clusterTopologyMapper) Bind() chan []node {
	ch := make(chan []node, 1)
	mapper.mu.Lock()
	ch <- mapper.current
	mapper.listeners.Insert(ch)
	mapper.mu.Unlock()
	return ch
}

func (mapper *clusterTopologyMapper) Unbind(ch chan []node) {
	mapper.mu.Lock()
	mapper.listeners.Remove(ch)
	mapper.mu.Unlock()
}

func (mapper *clusterTopologyMapper) Update(cfg *config.Config) {
	ctx, op := mapper.telemetry.Start(context.Background(), "Update")
	defer op.Complete()

	ctx, clearTimeout := context.WithTimeout(ctx, 10*time.Second)
	defer clearTimeout()

	databrokerURLs, err := cfg.Options.GetDataBrokerURLs()
	if err != nil {
		_ = op.Failure(fmt.Errorf("error getting databroker urls: %w", err))
		return
	}
	rawURLs := make([]string, len(databrokerURLs))
	for i, databrokerURL := range databrokerURLs {
		rawURLs[i] = databrokerURL.String()
	}
	mapper.mgr.Update(ctx, cfg, rawURLs)

	localInfo, err := mapper.local.ServerInfo(ctx, new(emptypb.Empty))
	if err != nil {
		_ = op.Failure(fmt.Errorf("rror retrieving local server info: %w", err))
		return
	}

	lookup := map[uint64]node{
		localInfo.NodeId: {
			isLocal:       true,
			nodeID:        localInfo.NodeId,
			serverVersion: localInfo.ServerVersion,
		},
	}

	type Result struct {
		nodes []node
		err   error
	}
	results := make(chan Result, len(rawURLs))
	for _, rawURL := range rawURLs {
		go func() {
			result := Result{}

			cc, err := mapper.mgr.GetClient(rawURL)
			if err != nil {
				result.err = err
				results <- result
				return
			}

			info, err := databrokerpb.NewDataBrokerServiceClient(cc).ServerInfo(ctx, new(emptypb.Empty))
			if err != nil {
				result.err = err
				results <- result
				return
			}

			result.nodes = append(result.nodes, node{
				url:           rawURL,
				nodeID:        info.NodeId,
				serverVersion: info.ServerVersion,
			})
			for _, peer := range info.Peers {
				result.nodes = append(result.nodes, node{
					url:           peer.Url,
					nodeID:        peer.NodeId,
					serverVersion: peer.ServerVersion,
				})
			}
			results <- result
		}()
	}

	remainingURLs := set.From(rawURLs)
outer:
	for i := 0; i < len(rawURLs); i++ {
		result := <-results
		if result.err != nil {
			log.Ctx(ctx).Error().Err(result.err).Msg("error querying databroker for server info")
			continue
		}

		for _, n := range result.nodes {
			lookup[n.nodeID] = mergeNodes(lookup[n.nodeID], n)
			remainingURLs.Remove(n.url)
			if remainingURLs.Size() == 0 {
				break outer
			}
		}
	}

	nodes := slices.Collect(maps.Values(lookup))
	slices.SortFunc(nodes, func(n1, n2 node) int {
		return cmp.Compare(n1.nodeID, n2.nodeID)
	})
	if len(nodes) > 0 {
		nodes[0].isLeader = true
	}

	// update the current topology

	mapper.mu.Lock()
	defer mapper.mu.Unlock()

	// nothing changed
	if slices.Equal(mapper.current, nodes) {
		return
	}

	// update and signal any listeners
	mapper.current = nodes
	for ch := range mapper.listeners.Items() {
		select {
		case <-ch:
		default:
		}
		ch <- mapper.current
	}
}

func (mapper *clusterTopologyMapper) Stop() {
	mapper.mgr.Stop()
}

type clusteredServer struct {
	telemetry telemetry.Component
	local     Server
	mapper    clusterTopologyMapper

	mu       sync.Mutex
	cfg      *config.Config
	leader   Server
	leaderID uint64

	databrokerpb.UnimplementedDataBrokerServiceServer
	registrypb.UnimplementedRegistryServer
}

func NewClusteredServer(tracerProvider oteltrace.TracerProvider, local Server) Server {
	return &clusteredServer{
		telemetry: *telemetry.NewComponent(tracerProvider, zerolog.InfoLevel, "databroker/clustered-server"),
		local:     local,
		mapper:    *newClusterTopologyMapper(tracerProvider, local),
	}
}

func (srv *clusteredServer) ServerInfo(ctx context.Context, req *emptypb.Empty) (res *databrokerpb.ServerInfoResponse, err error) {
	err = srv.withReadOnlyNode(ctx, func(s Server) error {
		var err error
		res, err = s.ServerInfo(ctx, req)
		return err
	})
	if err != nil {
		return nil, err
	}

	return res, err
}

func (srv *clusteredServer) Stop() {
	srv.mapper.Stop()
}

func (srv *clusteredServer) OnConfigChange(ctx context.Context, cfg *config.Config) {
	_, op := srv.telemetry.Start(ctx, "OnConfigChange")
	defer op.Complete()

	srv.mapper.Update(cfg)

	srv.mu.Lock()
	srv.cfg = cfg
	if srv.leader != nil {
		srv.leader.OnConfigChange(ctx, cfg)
	}
	srv.mu.Unlock()
}

func (srv *clusteredServer) withReadOnlyNode(ctx context.Context, fn func(Server) error) error {
	mode := GetIncomingClusterRequestMode(ctx)

	// for local mode we don't have to find the leader
	if mode == ClusterRequestModeLocal {
		return fn(srv.local)
	}

	// find the leader
	leader, err := srv.getLeader(ctx)
	if err != nil {
		return err
	}

	// leader is either a forwarding server or the local server

	switch mode {
	case ClusterRequestModeDefault:
		return fn(leader)
	case ClusterRequestModeLeader:
		// in leader mode we only allow calls if we're the leader
		if leader == srv.local {
			return fn(leader)
		}
		return databrokerpb.ErrNodeIsNotLeader
	default:
		return databrokerpb.ErrUnknownClusterRequestMode
	}
}

func (srv *clusteredServer) getLeader(ctx context.Context) (Server, error) {
	ctx, clearTimeout := context.WithTimeoutCause(ctx, time.Second*3, databrokerpb.ErrClusterHasNoLeader)
	defer clearTimeout()

	ch := srv.mapper.Bind()
	defer srv.mapper.Unbind(ch)

	for {
		select {
		case <-ctx.Done():
			return nil, context.Cause(ctx)
		case nodes := <-ch:
			for _, n := range nodes {
				if !n.isLeader {
					continue
				}

				if n.isLocal {
					return srv.local, nil
				}

				srv.mu.Lock()
				// stop the existing leader
				if srv.leader != nil && n.nodeID != srv.leaderID {
					srv.leader.Stop()
					srv.leader = nil
					srv.leaderID = 0
				}
				// start a new one
				if srv.leader == nil {
					srv.leader = NewForwardingServer(srv.cfg, n.url)
					srv.leaderID = n.nodeID
				}
				leader := srv.leader
				srv.mu.Unlock()

				return leader, nil
			}
		}
	}
}
