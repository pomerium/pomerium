package databroker_test

import (
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/pomerium/pomerium/internal/databroker"
	"github.com/pomerium/pomerium/internal/testutil"
	"github.com/pomerium/pomerium/pkg/databrokerutil"
	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
)

type mockCache struct {
	invalidateAllInvocations atomic.Int64
}

func (c *mockCache) InvalidateAll() {
	c.invalidateAllInvocations.Add(1)
}

func TestCacheInvalidator(t *testing.T) {
	t.Parallel()

	srv := databroker.NewBackendServer(noop.NewTracerProvider())
	t.Cleanup(srv.Stop)

	cache := new(mockCache)
	cacheInvalidator := databrokerpb.NewCacheInvalidator(cache)
	cc := testutil.NewGRPCServer(t,
		func(s *grpc.Server) {
			databrokerpb.RegisterDataBrokerServiceServer(s, srv)
		},
		grpc.WithChainStreamInterceptor(cacheInvalidator.StreamClientInterceptor),
		grpc.WithChainUnaryInterceptor(cacheInvalidator.UnaryClientInterceptor))
	t.Cleanup(func() { cc.Close() })

	client := databrokerpb.NewDataBrokerServiceClient(cc)

	_, _ = client.ServerInfo(t.Context(), new(emptypb.Empty))
	assert.Equal(t, int64(0), cache.invalidateAllInvocations.Load())

	client.Clear(t.Context(), new(emptypb.Empty))

	_, _ = client.ServerInfo(t.Context(), new(emptypb.Empty))
	assert.Equal(t, int64(1), cache.invalidateAllInvocations.Load())
	_, _ = client.ServerInfo(t.Context(), new(emptypb.Empty))
	assert.Equal(t, int64(1), cache.invalidateAllInvocations.Load())

	client.Clear(t.Context(), new(emptypb.Empty))

	_, _ = client.ServerInfo(t.Context(), new(emptypb.Empty))
	assert.Equal(t, int64(2), cache.invalidateAllInvocations.Load())
	_, _ = client.ServerInfo(t.Context(), new(emptypb.Empty))
	assert.Equal(t, int64(2), cache.invalidateAllInvocations.Load())

	_, _, _, _, _ = databrokerutil.InitialSync(t.Context(), client, &databrokerpb.SyncLatestRequest{})
	assert.Equal(t, int64(2), cache.invalidateAllInvocations.Load())

	client.Clear(t.Context(), new(emptypb.Empty))

	_, _, _, _, _ = databrokerutil.InitialSync(t.Context(), client, &databrokerpb.SyncLatestRequest{})
	assert.Equal(t, int64(3), cache.invalidateAllInvocations.Load())
}
