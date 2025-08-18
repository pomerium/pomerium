package databroker_test

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/databroker"
	"github.com/pomerium/pomerium/internal/testutil"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpcutil"
)

func TestSecuredServer(t *testing.T) {
	t.Parallel()

	underlying := databroker.NewBackendServer(noop.NewTracerProvider())
	secured := databroker.NewSecuredServer(underlying)

	sharedKey := cryptutil.NewKey()
	secured.OnConfigChange(t.Context(), &config.Config{
		Options: &config.Options{
			SharedKey: base64.StdEncoding.EncodeToString(sharedKey),
		},
	})

	cc := testutil.NewGRPCServer(t, func(s *grpc.Server) {
		databrokerpb.RegisterDataBrokerServiceServer(s, secured)
	})

	res, err := databrokerpb.NewDataBrokerServiceClient(cc).ServerInfo(t.Context(), new(emptypb.Empty))
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
	assert.Nil(t, res)

	ctx, err := grpcutil.WithSignedJWT(t.Context(), sharedKey)
	require.NoError(t, err)
	res, err = databrokerpb.NewDataBrokerServiceClient(cc).ServerInfo(ctx, new(emptypb.Empty))
	assert.NoError(t, err)
	assert.NotNil(t, res)
}
