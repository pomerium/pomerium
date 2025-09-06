package databroker_test

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/volatiletech/null/v9"
	"google.golang.org/grpc"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/databroker"
	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
)

func TestRaft(t *testing.T) {
	t.Parallel()

	li1, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = li1.Close() })
	s1 := grpc.NewServer()
	bsli1 := databrokerpb.NewByteStreamListener(li1.Addr())
	databrokerpb.RegisterByteStreamServer(s1, bsli1)
	go s1.Serve(li1)
	t.Cleanup(s1.Stop)

	li2, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = li2.Close() })
	s2 := grpc.NewServer()
	bsli2 := databrokerpb.NewByteStreamListener(li2.Addr())
	databrokerpb.RegisterByteStreamServer(s2, bsli2)
	go s2.Serve(li2)
	t.Cleanup(s2.Stop)

	li3, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = li3.Close() })
	s3 := grpc.NewServer()
	bsli3 := databrokerpb.NewByteStreamListener(li3.Addr())
	databrokerpb.RegisterByteStreamServer(s3, bsli3)
	go s3.Serve(li3)
	t.Cleanup(s3.Stop)

	cfg := &config.Config{
		Options: config.NewDefaultOptions(),
	}
	cfg.Options.DataBroker.ClusterNodes = []config.DataBrokerClusterNode{
		{
			ID:  "node-1",
			URL: li1.Addr().String(),
		}, {
			ID:  "node-2",
			URL: li2.Addr().String(),
		}, {
			ID:  "node-3",
			URL: li3.Addr().String(),
		},
	}

	cfg1 := cfg.Clone()
	cfg1.Options.DataBroker.ClusterNodeID = null.StringFrom("node-1")
	r1, err := databroker.NewRaft(cfg1, bsli1)
	require.NoError(t, err)
	t.Cleanup(func() { _ = r1.Shutdown().Error() })

	cfg2 := cfg.Clone()
	cfg2.Options.DataBroker.ClusterNodeID = null.StringFrom("node-2")
	r2, err := databroker.NewRaft(cfg2, bsli2)
	require.NoError(t, err)
	t.Cleanup(func() { _ = r2.Shutdown().Error() })

	cfg3 := cfg.Clone()
	cfg3.Options.DataBroker.ClusterNodeID = null.StringFrom("node-3")
	r3, err := databroker.NewRaft(cfg3, bsli3)
	require.NoError(t, err)
	t.Cleanup(func() { _ = r3.Shutdown().Error() })

	assert.Eventually(t, func() bool {
		return r1.Leader() != ""
	}, 10*time.Second, 100*time.Millisecond)
}
