package cluster

import (
	"cmp"
	"context"
	"maps"
	"slices"
	"sync"
	"time"

	"github.com/hashicorp/go-set/v3"
	"github.com/rs/zerolog"
	oteltrace "go.opentelemetry.io/otel/trace"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/telemetry"
	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpcutil"
)

type dataBrokerTopologySourceConfig struct {
	localNodeID        uint64
	localServerVersion uint64
	bootstrapURLs      []string
	pollingInterval    time.Duration
}

// A DataBrokerTopologySourceOption customizes the databroker topology source config.
type DataBrokerTopologySourceOption func(cfg *dataBrokerTopologySourceConfig)

// WithDataBrokerTopologySourceBootstrapURLs sets the bootstrap URLs in the databroker topology source config.
func WithDataBrokerTopologySourceBootstrapURLs(bootstrapURLs []string) DataBrokerTopologySourceOption {
	return func(cfg *dataBrokerTopologySourceConfig) {
		cfg.bootstrapURLs = bootstrapURLs
	}
}

// WithDataBrokerTopologySourceLocalNode sets the local node id and server version in the databroker topology source config.
func WithDataBrokerTopologySourceLocalNode(nodeID, serverVersion uint64) DataBrokerTopologySourceOption {
	return func(cfg *dataBrokerTopologySourceConfig) {
		cfg.localNodeID = nodeID
		cfg.localServerVersion = serverVersion
	}
}

// WithDataBrokerTopologySourcePollingInterval sets the polling interval in the databroker topology source config.
func WithDataBrokerTopologySourcePollingInterval(pollingInterval time.Duration) DataBrokerTopologySourceOption {
	return func(cfg *dataBrokerTopologySourceConfig) {
		cfg.pollingInterval = pollingInterval
	}
}

func getDataBrokerTopologySourceConfig(options ...DataBrokerTopologySourceOption) *dataBrokerTopologySourceConfig {
	cfg := new(dataBrokerTopologySourceConfig)
	WithDataBrokerTopologySourcePollingInterval(time.Minute)(cfg)
	for _, option := range options {
		option(cfg)
	}
	return cfg
}

// A DataBrokerTopologySource calls the ServerInfo method on databrokers to
// determine the cluster topology. IsLeader will be false for all nodes,
// so this topology should be handed to a leader elector before being used.
//
// The boostrap URLs are periodically polled to discover changes. Updating
// the options will also trigger rediscovery.
type DataBrokerTopologySource interface {
	TopologySource
	UpdateOptions(options ...DataBrokerTopologySourceOption)
}

type dataBrokerTopologySource struct {
	telemetry telemetry.Component
	Sink[Topology]
	clientManager grpcutil.ClientManager

	mu       sync.Mutex
	cfg      *dataBrokerTopologySourceConfig
	timer    *time.Timer
	previous Topology
}

// NewDataBrokerTopologySource creates a new DataBrokerTopologySource.
func NewDataBrokerTopologySource(tracerProvider oteltrace.TracerProvider, clientManager grpcutil.ClientManager, options ...DataBrokerTopologySourceOption) DataBrokerTopologySource {
	src := &dataBrokerTopologySource{
		telemetry:     *telemetry.NewComponent(tracerProvider, zerolog.DebugLevel, "databroker-topology-source"),
		clientManager: clientManager,
	}
	src.UpdateOptions(options...)
	return src
}

func (src *dataBrokerTopologySource) UpdateOptions(options ...DataBrokerTopologySourceOption) {
	src.mu.Lock()
	src.cfg = getDataBrokerTopologySourceConfig(options...)
	src.mu.Unlock()
	go src.update()
}

func (src *dataBrokerTopologySource) Stop() {
	src.mu.Lock()
	if src.timer != nil {
		src.timer.Stop()
		src.timer = nil
	}
	src.mu.Unlock()
}

func (src *dataBrokerTopologySource) update() {
	src.mu.Lock()
	defer src.mu.Unlock()

	next := src.discoverLocked()
	if !next.Equals(src.previous) {
		// the topology changed, send the update
		src.Send(next)
		src.previous = next
	}

	// stop any current timer
	if src.timer != nil {
		src.timer.Stop()
	}

	// start a new timer
	src.timer = time.AfterFunc(src.cfg.pollingInterval, src.update)
}

func (src *dataBrokerTopologySource) discoverLocked() Topology {
	ctx, op := src.telemetry.Start(context.Background(), "Discover")
	defer op.Complete()

	ctx, clearTimeout := context.WithTimeout(ctx, 10*time.Second)
	defer clearTimeout()

	lookup := map[uint64]Node{}

	// add the local node
	if src.cfg.localNodeID > 0 {
		lookup[src.cfg.localNodeID] = Node{
			IsLocal:       true,
			NodeID:        src.cfg.localNodeID,
			ServerVersion: src.cfg.localServerVersion,
		}
	}

	// query the ServerInfo for each bootstrap URL in parallel

	// In some network configurations it is possible that the local node will
	// not be accessible via its URL. We account for this by using the peer
	// list from the nodes that are accessible and once every URL has been
	// discovered we finish instead of waiting the full timeout.

	type Result struct {
		nodes []Node
		err   error
	}
	results := make(chan Result, len(src.cfg.bootstrapURLs))
	for _, bootstrapURL := range src.cfg.bootstrapURLs {
		go func() {
			result := Result{}

			client := databrokerpb.NewDataBrokerServiceClient(src.clientManager.GetClient(bootstrapURL))
			info, err := client.ServerInfo(WithOutgoingRequestMode(ctx, RequestModeLocal), new(emptypb.Empty))
			if err != nil {
				result.err = err
				results <- result
				return
			}

			result.nodes = append(result.nodes, Node{
				URL:           bootstrapURL,
				NodeID:        info.NodeId,
				ServerVersion: info.ServerVersion,
			})
			for _, peer := range info.Peers {
				result.nodes = append(result.nodes, Node{
					URL:           peer.Url,
					NodeID:        peer.NodeId,
					ServerVersion: peer.ServerVersion,
				})
			}
			results <- result
		}()
	}

	remainingURLs := set.From(src.cfg.bootstrapURLs)
outer:
	for range len(src.cfg.bootstrapURLs) {
		result := <-results
		if result.err != nil {
			log.Ctx(ctx).Error().Err(result.err).Msg("error querying databroker for server info")
			continue
		}

		for _, n := range result.nodes {
			lookup[n.NodeID] = lookup[n.NodeID].Merge(n)
			remainingURLs.Remove(n.URL)
			if remainingURLs.Size() == 0 {
				break outer
			}
		}
	}

	// create the topology, sorting by node id
	t := Topology{Nodes: slices.Collect(maps.Values(lookup))}
	slices.SortFunc(t.Nodes, func(n1, n2 Node) int {
		return cmp.Compare(n1.NodeID, n2.NodeID)
	})
	return t
}
