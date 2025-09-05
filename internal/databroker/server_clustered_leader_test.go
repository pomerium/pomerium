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

func TestClusteredLeaderServer(t *testing.T) {
	t.Parallel()

	local := databroker.NewBackendServer(noop.NewTracerProvider())
	leader := databroker.NewClusteredLeaderServer(local)

	cc := testutil.NewGRPCServer(t, func(s *grpc.Server) {
		databrokerpb.RegisterDataBrokerServiceServer(s, leader)
	})

	res1, err := local.ServerInfo(t.Context(), new(emptypb.Empty))
	assert.NoError(t, err)
	res2, err := databrokerpb.NewDataBrokerServiceClient(cc).ServerInfo(t.Context(), new(emptypb.Empty))
	assert.NoError(t, err)

	assert.Empty(t, cmp.Diff(res1, res2, protocmp.Transform()))
}
