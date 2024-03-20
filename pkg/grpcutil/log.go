package grpcutil

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"

	"github.com/pomerium/pomerium/internal/featureflags"
	"github.com/pomerium/pomerium/internal/log"
)

// LogConnectionState logs the state of a gRPC connection on change.
func LogConnectionState(ctx context.Context, conn *grpc.ClientConn) {
	if !featureflags.IsSet(featureflags.GRPCLogConnectionState) {
		return
	}

	var state connectivity.State = -1
	endpoint := conn.Target()
	for ctx.Err() == nil && state != connectivity.Shutdown {
		_ = conn.WaitForStateChange(ctx, state)
		state = conn.GetState()
		log.Ctx(ctx).Info().
			Str("endpoint", endpoint).
			Str("state", state.String()).
			Msg("grpc connection state")
	}
	log.Ctx(ctx).Info().
		Str("endpoint", endpoint).
		Str("state", state.String()).
		Msg("grpc connection shutdown")
}
