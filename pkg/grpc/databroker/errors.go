package databroker

import (
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var ErrServerNotAClusterMember = status.Error(codes.FailedPrecondition, "server is not a member of the databroker cluster")
