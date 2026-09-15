package databroker

import (
	"errors"
	"fmt"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// known errors
var (
	ErrClusterHasNoLeader         = newError(codes.Unavailable, "CLUSTER_HAS_NO_LEADER", "cluster has no leader")
	ErrDuplicateRecord            = newError(codes.InvalidArgument, "DUPLICATE_RECORD", "a conditional put names the same record more than once")
	ErrNoClusterLeaderGRPCAddress = newError(codes.FailedPrecondition, "NO_CLUSTER_LEADER_GRPC_ADDRESS", "cluster leader has no grpc_address")
	ErrNoClusterNodeID            = newError(codes.FailedPrecondition, "NO_CLUSTER_NODE_ID", "databroker_cluster_node_id is required but not set")
	ErrNoClusterNodes             = newError(codes.FailedPrecondition, "NO_CLUSTER_NODES", "databroker_cluster_nodes is required but not set")
	ErrNodeIsNotLeader            = newError(codes.FailedPrecondition, "NODE_IS_NOT_LEADER", "request cannot be handled because the node is not the leader")
	ErrNotInitialized             = newError(codes.Unavailable, "NOT_INITIALIZED", "not initialized")
	ErrRecordVersionMismatch      = newError(codes.Aborted, reasonRecordVersionMismatch, "record version does not match the stored version")
	ErrSetCheckpointNotSupported  = newError(codes.Unimplemented, "SET_CHECKPOINT_NOT_SUPPORTED", "SetCheckpoint is not supported")
	ErrUnknownClusterRequestMode  = newError(codes.InvalidArgument, "UNKNOWN_CLUSTER_REQUEST_MODE", "unknown cluster request mode")
)

const reasonRecordVersionMismatch = "RECORD_VERSION_MISMATCH"

// IsRecordVersionMismatch reports whether err is ErrRecordVersionMismatch, either
// locally (possibly wrapped) or after crossing a gRPC boundary.
func IsRecordVersionMismatch(err error) bool {
	if errors.Is(err, ErrRecordVersionMismatch) {
		return true
	}
	for _, detail := range status.Convert(err).Details() {
		if info, ok := detail.(*errdetails.ErrorInfo); ok && info.GetReason() == reasonRecordVersionMismatch {
			return true
		}
	}
	return false
}

// NewError creates a new error for use with gRPC.
func newError(code codes.Code, reason, message string) error {
	ei := &errdetails.ErrorInfo{
		Domain: "pomerium.com",
		Reason: reason,
	}

	s, err := status.New(code, fmt.Sprintf("%s: %s", reason, message)).WithDetails(ei)
	if err != nil {
		return err
	}
	return s.Err()
}
