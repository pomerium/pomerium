package databroker

import (
	"google.golang.org/grpc/codes"

	"github.com/pomerium/pomerium/pkg/grpcutil"
)

// known errors
var (
	ErrInvalidQueryFilter   = grpcutil.NewError(codes.InvalidArgument, "INVALID_QUERY_FILTER", "invalid query filter")
	ErrInvalidRecordVersion = grpcutil.NewError(codes.Aborted, "INVALID_RECORD_VERSION", "invalid record version")
	ErrInvalidServerVersion = grpcutil.NewError(codes.Aborted, "INVALID_SERVER_VERSION", "invalid server version")
	ErrLeaseAlreadyTaken    = grpcutil.NewError(codes.AlreadyExists, "LEASE_ALREADY_TAKEN", "lease is already taken")
	ErrLeaseLost            = grpcutil.NewError(codes.AlreadyExists, "LEASE_LOST", "lease lost")
	ErrRecordNotFound       = grpcutil.NewError(codes.NotFound, "RECORD_NOT_FOUND", "record not found")
)
