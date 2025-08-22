package databroker

import (
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// known errors
var (
	ErrClusterHasNoLeader        = newError(codes.FailedPrecondition, "CLUSTER_HAS_NO_LEADER", "request cannot be handled because the cluster has no leader")
	ErrForwardLimitExceeded      = newError(codes.FailedPrecondition, "FORWARD_LIMIT_EXCEEDED", "request exceeds the maximum number of forwards")
	ErrInvalidServerVersion      = newError(codes.Aborted, "INVALID_SERVER_VERSION", "invalid server version")
	ErrInvalidRecordVersion      = newError(codes.Aborted, "INVALID_RECORD_VERSION", "invalid record version")
	ErrNodeIsNotLeader           = newError(codes.FailedPrecondition, "NODE_IS_NOT_LEADER", "request cannot be handled because the node is not the leader")
	ErrUnknownClusterRequestMode = newError(codes.InvalidArgument, "UNKNOWN_CLUSTER_REQUEST_MODE", "unknown cluster request mode")
)

func newError(code codes.Code, reason, message string) error {
	st, err := status.New(code, message).WithDetails(&errdetails.ErrorInfo{
		Domain: "pomerium.com",
		Reason: reason,
	})
	if err != nil {
		return err
	}
	return st.Err()
}
