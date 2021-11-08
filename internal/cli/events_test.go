package cli

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"

	pb "github.com/pomerium/pomerium/pkg/grpc/cli"
)

func TestEventsBroadcast(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	b := NewEventsBroadcaster(ctx)
	expect := make(map[string][]*pb.ConnectionStatusUpdate)
	for id := 1; id <= 2; id++ {
		for peer := 1; peer <= 2; peer++ {
			for _, status := range []pb.ConnectionStatusUpdate_ConnectionStatus{
				pb.ConnectionStatusUpdate_CONNECTION_STATUS_CONNECTING,
				pb.ConnectionStatusUpdate_CONNECTION_STATUS_AUTH_REQUIRED,
				pb.ConnectionStatusUpdate_CONNECTION_STATUS_CONNECTED,
			} {
				idx := fmt.Sprintf("id%d", id)
				evt := &pb.ConnectionStatusUpdate{
					Id:       idx,
					PeerAddr: fmt.Sprintf("localhost:999%d", peer),
					Status:   status,
				}
				expect[idx] = append(expect[idx], evt)
				b.Update(ctx, evt)
			}
		}
	}

	// connect, should receive historical events
	sCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	ch, err := b.Subscribe(sCtx, "id1")
	require.NoError(t, err)

	for _, want := range expect["id1"] {
		got := <-ch
		assert.Empty(t, cmp.Diff(want, got, protocmp.Transform()))
	}

	// reset historical data buffer
	b.Reset(ctx, "id2")

	sCtx, cancel = context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	ch, err = b.Subscribe(sCtx, "id2")
	require.NoError(t, err)

	select {
	case got := <-ch:
		t.Error("expected no historical data after reset", got)
	default:
	}
}
