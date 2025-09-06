package databroker_test

import (
	"fmt"
	"net"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/volatiletech/null/v9"
	"go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/databroker"
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

	cfg := &config.Config{Options: config.NewDefaultOptions()}
	cfg.Options.DataBroker.ClusterLeaderID = null.StringFrom("node-1")
	cfg.Options.DataBroker.ClusterNodes = []config.DataBrokerClusterNode{
		{ID: "node-1", URL: fmt.Sprintf("http://%s", li1.Addr().String())},
		{ID: "node-2", URL: fmt.Sprintf("http://%s", li2.Addr().String())},
		{ID: "node-3", URL: fmt.Sprintf("http://%s", li3.Addr().String())},
	}

	cfg1 := cfg.Clone()
	cfg1.Options.DataBroker.ClusterNodeID = null.StringFrom("node-1")
	local1 := databroker.NewBackendServer(noop.NewTracerProvider())
	cluster1 := databroker.NewClusteredServer(noop.NewTracerProvider(), local1)
	cluster1.OnConfigChange(t.Context(), cfg1)
	s1 := grpc.NewServer()
	databrokerpb.RegisterDataBrokerServiceServer(s1, cluster1)
	go s1.Serve(li1)

	cfg2 := cfg.Clone()
	cfg2.Options.DataBroker.ClusterNodeID = null.StringFrom("node-2")
	local2 := databroker.NewBackendServer(noop.NewTracerProvider())
	cluster2 := databroker.NewClusteredServer(noop.NewTracerProvider(), local2)
	cluster2.OnConfigChange(t.Context(), cfg2)
	s2 := grpc.NewServer()
	databrokerpb.RegisterDataBrokerServiceServer(s2, cluster2)
	go s2.Serve(li1)

	cfg3 := cfg.Clone()
	cfg3.Options.DataBroker.ClusterNodeID = null.StringFrom("node-3")
	local3 := databroker.NewBackendServer(noop.NewTracerProvider())
	cluster3 := databroker.NewClusteredServer(noop.NewTracerProvider(), local3)
	cluster3.OnConfigChange(t.Context(), cfg3)
	s3 := grpc.NewServer()
	databrokerpb.RegisterDataBrokerServiceServer(s3, cluster3)
	go s3.Serve(li1)

	res1, err := cluster1.ServerInfo(t.Context(), new(emptypb.Empty))
	require.NoError(t, err)
	res2, err := cluster2.ServerInfo(t.Context(), new(emptypb.Empty))
	require.NoError(t, err)
	res3, err := cluster3.ServerInfo(t.Context(), new(emptypb.Empty))
	require.NoError(t, err)

	assert.Empty(t, cmp.Diff(res1, res2, protocmp.Transform()))
	assert.Empty(t, cmp.Diff(res2, res3, protocmp.Transform()))
}
