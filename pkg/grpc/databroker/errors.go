package databroker

import (
	"google.golang.org/grpc/codes"

	"github.com/pomerium/pomerium/pkg/grpcutil"
)

// known errors
var (
	ErrClusterHasNoLeader         = grpcutil.NewError(codes.Unavailable, "CLUSTER_HAS_NO_LEADER", "cluster has no leader")
	ErrNoClusterLeaderGRPCAddress = grpcutil.NewError(codes.FailedPrecondition, "NO_CLUSTER_LEADER_GRPC_ADDRESS", "cluster leader has no grpc_address")
	ErrNoClusterNodeID            = grpcutil.NewError(codes.FailedPrecondition, "NO_CLUSTER_NODE_ID", "databroker_cluster_node_id is required but not set")
	ErrNoClusterNodes             = grpcutil.NewError(codes.FailedPrecondition, "NO_CLUSTER_NODES", "databroker_cluster_nodes is required but not set")
	ErrNodeIsNotLeader            = grpcutil.NewError(codes.FailedPrecondition, "NODE_IS_NOT_LEADER", "request cannot be handled because the node is not the leader")
	ErrNotInitialized             = grpcutil.NewError(codes.Unavailable, "NOT_INITIALIZED", "not initialized")
	ErrSetCheckpointNotSupported  = grpcutil.NewError(codes.Unimplemented, "SET_CHECKPOINT_NOT_SUPPORTED", "SetCheckpoint is not supported")
	ErrUnknownClusterRequestMode  = grpcutil.NewError(codes.InvalidArgument, "UNKNOWN_CLUSTER_REQUEST_MODE", "unknown cluster request mode")
)
