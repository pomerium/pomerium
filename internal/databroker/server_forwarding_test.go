package databroker_test

import (
	"encoding/base64"
	"net"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/databroker"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
)

func TestForwardingServer(t *testing.T) {
	t.Parallel()

	sharedKey := cryptutil.NewKey()

	t.Run("forwards requests", func(t *testing.T) {
		t.Parallel()

		cfg := &config.Config{Options: &config.Options{
			SharedKey: base64.StdEncoding.EncodeToString(sharedKey),
		}}

		srv1 := databroker.NewSecuredServer(databroker.NewBackendServer(noop.NewTracerProvider()))
		t.Cleanup(srv1.Stop)
		srv1.OnConfigChange(t.Context(), cfg)
		addr1 := newTestServer(t, srv1)

		c1, err := databroker.NewClientForConfig(cfg, "http://"+addr1)
		require.NoError(t, err)

		srv2 := databroker.NewForwardingServer(c1)
		t.Cleanup(srv2.Stop)
		srv2.OnConfigChange(t.Context(), cfg)
		addr2 := newTestServer(t, srv2)

		c2, err := databroker.NewClientForConfig(cfg, "http://"+addr2)
		require.NoError(t, err)

		ctx := t.Context()
		require.NoError(t, err)
		res1, err := databrokerpb.NewDataBrokerServiceClient(c1).ServerInfo(ctx, new(emptypb.Empty))
		assert.NoError(t, err)
		res2, err := databrokerpb.NewDataBrokerServiceClient(c2).ServerInfo(ctx, new(emptypb.Empty))
		assert.NoError(t, err)
		assert.Empty(t, cmp.Diff(res1, res2, protocmp.Transform()))
	})
	t.Run("aborts too many forwards", func(t *testing.T) {
		t.Parallel()

		cfg := &config.Config{Options: &config.Options{
			SharedKey: base64.StdEncoding.EncodeToString(sharedKey),
		}}

		srv1 := databroker.NewSecuredServer(databroker.NewBackendServer(noop.NewTracerProvider()))
		t.Cleanup(srv1.Stop)
		srv1.OnConfigChange(t.Context(), cfg)
		addr1 := newTestServer(t, srv1)

		c1, err := databroker.NewClientForConfig(cfg, "http://"+addr1)
		require.NoError(t, err)

		srv2 := databroker.NewForwardingServer(c1)
		t.Cleanup(srv2.Stop)
		srv2.OnConfigChange(t.Context(), cfg)
		addr2 := newTestServer(t, srv2)

		c2, err := databroker.NewClientForConfig(cfg, "http://"+addr2)
		require.NoError(t, err)

		srv3 := databroker.NewForwardingServer(c2)
		t.Cleanup(srv3.Stop)
		srv3.OnConfigChange(t.Context(), cfg)
		addr3 := newTestServer(t, srv3)

		cc, err := databroker.NewClientForConfig(cfg, "http://"+addr3)
		require.NoError(t, err)

		ctx := t.Context()
		require.NoError(t, err)
		res, err := databrokerpb.NewDataBrokerServiceClient(cc).ServerInfo(ctx, new(emptypb.Empty))
		assert.Error(t, err)
		assert.Equal(t, codes.FailedPrecondition, status.Code(err))
		assert.Nil(t, res)
	})
}

func newTestServer(tb testing.TB, srv databroker.Server) (addr string) {
	li, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(tb, err)
	tb.Cleanup(func() { _ = li.Close() })

	s := grpc.NewServer()
	databrokerpb.RegisterDataBrokerServiceServer(s, srv)
	go s.Serve(li)
	tb.Cleanup(func() { s.Stop() })

	return li.Addr().String()
}
