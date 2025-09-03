package grpcutil

import (
	"fmt"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// errors
var (
	ErrForwardingCycleDetected = NewError(codes.Internal, "FORWARDING_CYCLE_DETECTED", "forwarding cycle detected")
	ErrMissingJWT              = NewError(codes.Unauthenticated, "MISSING_JWT", "missing signed jwt")
	ErrInvalidJWT              = NewError(codes.Unauthenticated, "INVALID_JWT", "invalid signed jwt")
)

// NewError creates a new error for use with gRPC.
func NewError(code codes.Code, reason, message string, pairs ...string) error {
	ei := &errdetails.ErrorInfo{
		Domain: "pomerium.com",
		Reason: reason,
	}

	// add metadata
	for i := 1; i < len(pairs); i += 2 {
		if ei.Metadata == nil {
			ei.Metadata = make(map[string]string)
		}
		ei.Metadata[pairs[i-1]] = pairs[i]
	}

	s, err := status.New(code, fmt.Sprintf("%s: %s", reason, message)).WithDetails(ei)
	if err != nil {
		return err
	}
	return s.Err()
}
