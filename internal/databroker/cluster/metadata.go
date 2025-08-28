package cluster

import (
	"context"

	"google.golang.org/grpc/metadata"
)

// RequestMode indicates how a node should handle requests.
type RequestMode string

const (
	// A node that receives a request with the default cluster request mode
	// will respond using local data if it is the current leader or forward
	// the request to the leader if not.
	RequestModeDefault RequestMode = "default"
	// A node that receives a request with the local cluster request mode
	// will respond using local data if it is the leader or for read-only
	// requests. If it is not the leader it will return an error for
	// read-write requests.
	RequestModeLocal RequestMode = "local"
	// A node that receives a request with the leader cluster request mode
	// will respond using local data if it is the leader. If it is not the
	// leader it will return an error.
	RequestModeLeader RequestMode = "leader"
)

// RequestModeKey is the key for the cluster request mode in the
// gRPC metadata.
const RequestModeKey = "pomerium-cluster-request-mode"

// WithOutgoingRequestMode sets the ougoing cluster request mode.
func WithOutgoingRequestMode(ctx context.Context, requestMode RequestMode) context.Context {
	return metadata.AppendToOutgoingContext(ctx, RequestModeKey, string(requestMode))
}

// GetIncomingRequestMode gets the incoing cluster request mode.
func GetIncomingRequestMode(ctx context.Context) RequestMode {
	values := metadata.ValueFromIncomingContext(ctx, RequestModeKey)
	if len(values) == 0 {
		return RequestModeDefault
	}
	return RequestMode(values[len(values)-1])
}
