package databroker

import (
	"google.golang.org/grpc/codes"

	"github.com/pomerium/pomerium/pkg/grpcutil"
)

// known errors
var (
	ErrNodeIsNotLeader           = grpcutil.NewError(codes.FailedPrecondition, "NODE_IS_NOT_LEADER", "request cannot be handled because the node is not the leader")
	ErrUnknownClusterRequestMode = grpcutil.NewError(codes.InvalidArgument, "UNKNOWN_CLUSTER_REQUEST_MODE", "unknown cluster request mode")
)
