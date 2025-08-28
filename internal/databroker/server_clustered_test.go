package databroker_test

import (
	"fmt"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/databroker"
	"github.com/pomerium/pomerium/internal/testutil"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
)

func TestClusteredServer(t *testing.T) {
	t.Parallel()

	li1, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = li1.Close() })
	li2, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = li2.Close() })
	li3, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = li3.Close() })

	srv1 := databroker.NewBackendServer(noop.NewTracerProvider())
	s1 := grpc.NewServer()
	databrokerpb.RegisterDataBrokerServiceServer(s1, srv1)
	go s1.Serve(li1)
	t.Cleanup(s1.Stop)

	srv2 := databroker.NewBackendServer(noop.NewTracerProvider())
	s2 := grpc.NewServer()
	databrokerpb.RegisterDataBrokerServiceServer(s2, srv2)
	go s2.Serve(li2)
	t.Cleanup(s2.Stop)

	srv3 := databroker.NewBackendServer(noop.NewTracerProvider())
	s3 := grpc.NewServer()
	databrokerpb.RegisterDataBrokerServiceServer(s3, srv3)
	go s3.Serve(li3)
	t.Cleanup(s3.Stop)

	srv4 := databroker.NewClusteredServer(noop.NewTracerProvider(), srv1, &config.Config{
		Options: &config.Options{
			DataBrokerURLStrings: []string{
				fmt.Sprintf("http://%s/", li1.Addr().String()),
				fmt.Sprintf("http://%s/", li2.Addr().String()),
				fmt.Sprintf("http://%s/", li3.Addr().String()),
			},
			SharedKey: cryptutil.NewBase64Key(),
		},
	})

	cc1 := testutil.NewGRPCServer(t, func(s *grpc.Server) {
		databrokerpb.RegisterDataBrokerServiceServer(s, srv4)
	})
	res1, err := srv1.ServerInfo(t.Context(), new(emptypb.Empty))
	assert.NoError(t, err)
	res2, err := srv2.ServerInfo(t.Context(), new(emptypb.Empty))
	assert.NoError(t, err)
	res3, err := srv3.ServerInfo(t.Context(), new(emptypb.Empty))
	assert.NoError(t, err)
	res4, err := databrokerpb.NewDataBrokerServiceClient(cc1).ServerInfo(t.Context(), new(emptypb.Empty))
	assert.NoError(t, err)
	assert.Equal(t, min(res1.NodeId, res2.NodeId, res3.NodeId), res4.NodeId)
}
