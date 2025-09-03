package databroker_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/pomerium/pomerium/internal/databroker"
	"github.com/pomerium/pomerium/internal/testutil"
	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
)

func TestForwardingServer(t *testing.T) {
	t.Parallel()

	srv := databroker.NewBackendServer(noop.NewTracerProvider())
	cc := testutil.NewGRPCServer(t, func(s *grpc.Server) {
		databrokerpb.RegisterDataBrokerServiceServer(s, srv)
	})

	databroker.NewForwardingServer(cc)

	res1, err := srv.ServerInfo(t.Context(), new(emptypb.Empty))
	assert.NoError(t, err)
	res2, err := databrokerpb.NewDataBrokerServiceClient(cc).ServerInfo(t.Context(), new(emptypb.Empty))
	assert.NoError(t, err)

	assert.Empty(t, cmp.Diff(res1, res2, protocmp.Transform()))
}
