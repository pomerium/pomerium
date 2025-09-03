package databroker_test

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/pomerium/pomerium/internal/databroker"
	"github.com/pomerium/pomerium/internal/testutil"
	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
)

func TestErroringServer(t *testing.T) {
	t.Parallel()

	erroring := databroker.NewErroringServer(errors.New("TEST ERROR"))

	cc := testutil.NewGRPCServer(t, func(s *grpc.Server) {
		databrokerpb.RegisterDataBrokerServiceServer(s, erroring)
	})

	res, err := databrokerpb.NewDataBrokerServiceClient(cc).ServerInfo(t.Context(), new(emptypb.Empty))
	assert.ErrorContains(t, err, "TEST ERROR")
	assert.Nil(t, res)
}
