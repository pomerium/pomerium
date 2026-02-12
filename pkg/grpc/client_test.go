package grpc

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

// newTestGRPCServer creates a minimal gRPC server using a bufconn listener
// and returns a dial option that connects to it.
func newTestGRPCServer(t *testing.T) grpc.DialOption {
	t.Helper()
	lis := bufconn.Listen(1024 * 1024)
	srv := grpc.NewServer()
	t.Cleanup(func() { srv.Stop() })
	go srv.Serve(lis)
	return grpc.WithContextDialer(func(_ context.Context, _ string) (net.Conn, error) {
		return lis.Dial()
	})
}

func TestCachedOutboundGRPClientConn_GetWithSameContext(t *testing.T) {
	// This test verifies that calling Get() twice with the same (still-alive)
	// context but different options does not deadlock.
	//
	// The bug: when Get() is called a second time, it calls stopCleanup() to
	// prevent the AfterFunc (registered with the first call's context) from
	// running. If the context is still alive, stopCleanup() succeeds and the
	// AfterFunc never fires — meaning close(done) never happens. Then
	// <-cache.done blocks forever.
	dialer := newTestGRPCServer(t)

	cache := &CachedOutboundGRPClientConn{}
	ctx := t.Context()

	opts1 := &OutboundOptions{OutboundPort: "1234", InstallationID: "a"}
	cc1, err := cache.Get(ctx, opts1,
		dialer, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	require.NotNil(t, cc1)

	// Call Get() a second time with different options but the SAME context.
	// The context is still alive (not cancelled). This must not deadlock.
	opts2 := &OutboundOptions{OutboundPort: "1234", InstallationID: "b"}

	done := make(chan struct{})
	go func() {
		defer close(done)
		cc2, err := cache.Get(ctx, opts2,
			dialer, grpc.WithTransportCredentials(insecure.NewCredentials()))
		assert.NoError(t, err)
		assert.NotNil(t, cc2)
	}()

	select {
	case <-done:
		// success — Get() returned without deadlocking
	case <-time.After(5 * time.Second):
		t.Fatal("deadlock: CachedOutboundGRPClientConn.Get() blocked for 5s; " +
			"stopCleanup() prevented the AfterFunc from closing the done channel")
	}
}

func TestCachedOutboundGRPClientConn_GetWithCancelledContext(t *testing.T) {
	// This test verifies the non-deadlocking path: when the first call's
	// context is cancelled before the second Get() call, the AfterFunc fires,
	// close(done) happens, and <-cache.done unblocks.
	dialer := newTestGRPCServer(t)

	cache := &CachedOutboundGRPClientConn{}
	ctx1, cancel1 := context.WithCancel(t.Context())

	opts1 := &OutboundOptions{OutboundPort: "1234", InstallationID: "a"}
	cc1, err := cache.Get(ctx1, opts1,
		dialer, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	require.NotNil(t, cc1)

	// Cancel the first context — this allows the AfterFunc to fire.
	cancel1()

	// Give the AfterFunc goroutine a moment to run.
	time.Sleep(50 * time.Millisecond)

	// Now call Get() with a new context and different options.
	ctx2 := t.Context()
	opts2 := &OutboundOptions{OutboundPort: "1234", InstallationID: "b"}

	done := make(chan struct{})
	go func() {
		defer close(done)
		cc2, err := cache.Get(ctx2, opts2,
			dialer, grpc.WithTransportCredentials(insecure.NewCredentials()))
		assert.NoError(t, err)
		assert.NotNil(t, cc2)
	}()

	select {
	case <-done:
		// success
	case <-time.After(5 * time.Second):
		t.Fatal("Get() blocked unexpectedly even though the first context was cancelled")
	}
}

func TestCachedOutboundGRPClientConn_GetSameOptions(t *testing.T) {
	// When options haven't changed, Get() should return the cached connection.
	dialer := newTestGRPCServer(t)

	cache := &CachedOutboundGRPClientConn{}
	ctx := t.Context()

	opts := &OutboundOptions{OutboundPort: "1234", InstallationID: "a"}
	cc1, err := cache.Get(ctx, opts,
		dialer, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)

	cc2, err := cache.Get(ctx, opts,
		dialer, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)

	assert.Same(t, cc1, cc2, "same options should return the cached connection")
}
