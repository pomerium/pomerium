package databroker

import (
	"context"
	"testing"

	"github.com/cenkalti/backoff/v4"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/pomerium/pomerium/internal/telemetry"
	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
)

// stoppingServer stops the follower in the middle of a call and then fails
// the call the way a gRPC stream does when its context is canceled.
type stoppingServer struct {
	Server
	stop func()
}

func (s stoppingServer) fail() error {
	s.stop()
	return status.Error(codes.Canceled, context.Canceled.Error())
}

func (s stoppingServer) GetCheckpoint(context.Context, *databrokerpb.GetCheckpointRequest) (*databrokerpb.GetCheckpointResponse, error) {
	return nil, s.fail()
}

func (s stoppingServer) Clear(context.Context, *emptypb.Empty) (*databrokerpb.ClearResponse, error) {
	return nil, s.fail()
}

func TestClusteredFollowerServerStopped(t *testing.T) {
	newServer := func(t *testing.T) (*clusteredFollowerServer, context.Context) {
		ctx, cancel := context.WithCancelCause(t.Context())
		return &clusteredFollowerServer{
			telemetry: *telemetry.NewComponent(noop.NewTracerProvider(), zerolog.DebugLevel, "test"),
			local:     stoppingServer{stop: func() { cancel(errClusteredFollowerServerStopped) }},
		}, ctx
	}

	t.Run("sync", func(t *testing.T) {
		srv, ctx := newServer(t)
		assert.ErrorIs(t, srv.sync(ctx, backoff.NewExponentialBackOff(), true), errClusteredFollowerServerStopped)
	})
	t.Run("sync latest", func(t *testing.T) {
		srv, ctx := newServer(t)
		assert.ErrorIs(t, srv.syncLatest(ctx, backoff.NewExponentialBackOff()), errClusteredFollowerServerStopped)
	})
}
