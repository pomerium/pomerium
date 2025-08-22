package databroker

import (
	"context"

	"google.golang.org/grpc/metadata"
)

// ClusterRequestMode indicates how a node should handle requests.
type ClusterRequestMode string

const (
	// A node that receives a request with the default cluster request mode
	// will respond using local data if it is the current leader or forward
	// the request to the leader if not.
	ClusterRequestModeDefault ClusterRequestMode = "default"
	// A node that receives a request with the local cluster request mode
	// will respond using local data if it is the leader or for read-only
	// requests. If it is not the leader it will return an error for
	// read-write requests.
	ClusterRequestModeLocal ClusterRequestMode = "local"
	// A node that receives a request with the leader cluster request mode
	// will respond using local data if it is the leader. If it is not the
	// leader it will return an error.
	ClusterRequestModeLeader ClusterRequestMode = "leader"
)

// ClusterRequestModeKey is the key for the cluster request mode in the
// gRPC metadata.
const ClusterRequestModeKey = "pomerium-cluster-request-mode"

// WithOutgoingClusterRequestMode sets the ougoing cluster request mode.
func WithOutgoingClusterRequestMode(ctx context.Context, clusterRequestMode ClusterRequestMode) context.Context {
	return metadata.AppendToOutgoingContext(ctx, ClusterRequestModeKey, string(clusterRequestMode))
}

// GetIncomingClusterRequestMode gets the incoing cluster request mode.
func GetIncomingClusterRequestMode(ctx context.Context) ClusterRequestMode {
	values := metadata.ValueFromIncomingContext(ctx, ClusterRequestModeKey)
	if len(values) == 0 {
		return ClusterRequestModeDefault
	}
	return ClusterRequestMode(values[len(values)-1])
}
