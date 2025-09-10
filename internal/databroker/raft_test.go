package databroker_test

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/volatiletech/null/v9"
	"go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/grpc"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/databroker"
	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
)

func TestRaft(t *testing.T) {
	t.Parallel()

	startServer := func() (net.Addr, databrokerpb.ByteStreamListener) {
		li, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		t.Cleanup(func() { _ = li.Close() })
		s1 := grpc.NewServer()
		bsli := databrokerpb.NewByteStreamListener()
		databrokerpb.RegisterByteStreamServer(s1, bsli)
		go s1.Serve(li)
		t.Cleanup(s1.Stop)
		return li.Addr(), bsli
	}

	addr1, s1 := startServer()
	addr2, s2 := startServer()
	addr3, s3 := startServer()

	cfg := &config.Config{
		Options: config.NewDefaultOptions(),
	}
	cfg.Options.DataBroker.ClusterNodes = []config.DataBrokerClusterNode{
		{
			ID:  "node-1",
			URL: fmt.Sprintf("http://%s", addr1.String()),
		}, {
			ID:  "node-2",
			URL: fmt.Sprintf("http://%s", addr2.String()),
		}, {
			ID:  "node-3",
			URL: fmt.Sprintf("http://%s", addr3.String()),
		},
	}

	clientManager := databroker.NewClientManager(noop.NewTracerProvider())
	clientManager.OnConfigChange(t.Context(), cfg)

	cfg1 := cfg.Clone()
	cfg1.Options.DataBroker.ClusterNodeID = null.StringFrom("node-1")
	r1, err := databroker.NewRaft(cfg1, s1, clientManager)
	require.NoError(t, err)
	t.Cleanup(func() { _ = r1.Shutdown().Error() })

	cfg2 := cfg.Clone()
	cfg2.Options.DataBroker.ClusterNodeID = null.StringFrom("node-2")
	r2, err := databroker.NewRaft(cfg2, s2, clientManager)
	require.NoError(t, err)
	t.Cleanup(func() { _ = r2.Shutdown().Error() })

	cfg3 := cfg.Clone()
	cfg3.Options.DataBroker.ClusterNodeID = null.StringFrom("node-3")
	r3, err := databroker.NewRaft(cfg3, s3, clientManager)
	require.NoError(t, err)
	t.Cleanup(func() { _ = r3.Shutdown().Error() })

	assert.Eventually(t, func() bool {
		return r1.Leader() != ""
	}, 10*time.Second, 100*time.Millisecond)
}
