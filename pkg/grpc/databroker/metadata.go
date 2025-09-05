package databroker

import (
	"context"

	"google.golang.org/grpc/metadata"
)

// ClusterRequestMode determines how a node in a cluster should handle requests.
type ClusterRequestMode string

const (
	// ClusterRequestModeDefault indicates that requests will either be handled
	// by the local databroker storage backend if the node is the leader, or
	// forwarded to the leader if the node is a follower.
	ClusterRequestModeDefault ClusterRequestMode = "default"
	// ClusterRequestModeLocal indicates that read-only requests to either a
	// follower or the leader should be handled locally. Read-write requests
	// will always return an error on follower nodes and work properly on the
	// leader node.
	ClusterRequestModeLocal ClusterRequestMode = "local"
	// ClusterRequestModeLeader indicates that a request should only be handled
	// by the leader node.
	ClusterRequestModeLeader ClusterRequestMode = "leader"
)

// ClusterRequestModeKey is the key for the cluster request mode in the gRPC
// metadata.
const ClusterRequestModeKey = "pomerium-cluster-request-mode"

// WithOutgoingClusterRequestMode sets the outgoing cluster request mode.
func WithOutgoingClusterRequestMode(ctx context.Context, clusterRequestMode ClusterRequestMode) context.Context {
	md, ok := metadata.FromOutgoingContext(ctx)
	if !ok {
		md = make(metadata.MD)
	}
	md.Set(ClusterRequestModeKey, string(clusterRequestMode))
	return metadata.NewOutgoingContext(ctx, md)
}

// GetIncomingClusterRequestMode gets the incoming cluster request mode.
func GetIncomingClusterRequestMode(ctx context.Context) ClusterRequestMode {
	values := metadata.ValueFromIncomingContext(ctx, ClusterRequestModeKey)
	if len(values) == 0 {
		return ClusterRequestModeDefault
	}
	return ClusterRequestMode(values[len(values)-1])
}
