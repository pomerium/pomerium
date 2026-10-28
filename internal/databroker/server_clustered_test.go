package databroker_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"net"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/volatiletech/null/v9"
	"go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/databroker"
	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

func TestClusteredServer(t *testing.T) {
	t.Parallel()

	li1, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { li1.Close() })
	li2, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { li2.Close() })
	li3, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { li3.Close() })

	cfg := &config.Config{
		Options: &config.Options{
			SharedKey: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x00}, 32)),
			DataBroker: config.DataBrokerOptions{
				ClusterLeaderID: null.StringFrom("cluster1"),
				ClusterNodes: config.DataBrokerClusterNodes{
					{ID: "cluster1", GRPCAddress: "http://" + li1.Addr().String()},
					{ID: "cluster2", GRPCAddress: "http://" + li2.Addr().String()},
					{ID: "cluster3", GRPCAddress: "http://" + li3.Addr().String()},
				},
			},
		},
	}

	cfg1 := cfg.Clone()
	cfg1.Options.DataBroker.ClusterNodeID = null.StringFrom("cluster1")
	backend1 := databroker.NewBackendServer(noop.NewTracerProvider())
	cluster1 := databroker.NewClusteredServer(noop.NewTracerProvider(), backend1, cfg1)

	cfg2 := cfg.Clone()
	cfg2.Options.DataBroker.ClusterNodeID = null.StringFrom("cluster2")
	backend2 := databroker.NewBackendServer(noop.NewTracerProvider())
	cluster2 := databroker.NewClusteredServer(noop.NewTracerProvider(), backend2, cfg2)

	cfg3 := cfg.Clone()
	cfg3.Options.DataBroker.ClusterNodeID = null.StringFrom("cluster3")
	backend3 := databroker.NewBackendServer(noop.NewTracerProvider())
	cluster3 := databroker.NewClusteredServer(noop.NewTracerProvider(), backend3, cfg3)

	srv1 := grpc.NewServer()
	databrokerpb.RegisterDataBrokerServiceServer(srv1, cluster1)
	go srv1.Serve(li1)
	srv2 := grpc.NewServer()
	databrokerpb.RegisterDataBrokerServiceServer(srv2, cluster2)
	go srv2.Serve(li2)
	srv3 := grpc.NewServer()
	databrokerpb.RegisterDataBrokerServiceServer(srv3, cluster3)
	go srv3.Serve(li3)

	cc1, err := grpc.NewClient(li1.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { cc1.Close() })
	// client1 := databrokerpb.NewDataBrokerServiceClient(cc1)

	cc2, err := grpc.NewClient(li2.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { cc2.Close() })
	client2 := databrokerpb.NewDataBrokerServiceClient(cc2)

	cc3, err := grpc.NewClient(li3.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { cc3.Close() })
	client3 := databrokerpb.NewDataBrokerServiceClient(cc3)

	infoFromBackend, err := backend1.ServerInfo(t.Context(), new(emptypb.Empty))
	require.NoError(t, err)
	infoFromCluster, err := client3.ServerInfo(t.Context(), new(emptypb.Empty))
	require.NoError(t, err)
	assert.Empty(t, cmp.Diff(infoFromBackend, infoFromCluster, protocmp.Transform()),
		"should return server info from the leader")

	// start a stream and then initiate a leadership change. The stream should return an error.
	streamStarted := make(chan struct{})
	streamGotFirstMessage := make(chan struct{})
	streamGotSecondMessage := make(chan struct{})
	streamStopped := make(chan struct{})
	go func() {
		ctx, cancelStream := context.WithCancel(t.Context())
		defer cancelStream()

		stream, err := client3.Sync(ctx, &databrokerpb.SyncRequest{
			ServerVersion: infoFromCluster.GetServerVersion(),
			RecordVersion: infoFromCluster.GetLatestRecordVersion(),
		})
		if err != nil {
			t.Error(err)
			return
		}

		close(streamStarted)

		for i := 0; ; i++ {
			res, err := stream.Recv()
			if err != nil {
				close(streamStopped)
				return
			}

			if i == 0 {
				close(streamGotFirstMessage)
			} else if i == 1 {
				close(streamGotSecondMessage)
			}

			t.Log("received", res)
		}
	}()

	select {
	case <-t.Context().Done():
		return
	case <-streamStarted:
	}

	_, err = client3.Put(t.Context(), &databrokerpb.PutRequest{
		Records: []*databrokerpb.Record{{
			Type: "test", Id: "record1", Data: protoutil.NewAnyString("test"),
		}},
	})
	require.NoError(t, err)

	select {
	case <-t.Context().Done():
		return
	case <-streamGotFirstMessage:
	}

	// lose the leader on all the clusters
	cfg1 = cfg1.Clone()
	cfg1.Options.DataBroker.ClusterLeaderID = null.StringFrom("INVALID")
	cluster1.OnConfigChange(t.Context(), cfg1)

	cfg2 = cfg2.Clone()
	cfg2.Options.DataBroker.ClusterLeaderID = null.StringFrom("INVALID")
	cluster2.OnConfigChange(t.Context(), cfg2)

	cfg3 = cfg3.Clone()
	cfg3.Options.DataBroker.ClusterLeaderID = null.StringFrom("INVALID")
	cluster3.OnConfigChange(t.Context(), cfg3)

	// update the leader back to cluster1, but don't inform cluster3 just yet

	cfg1 = cfg1.Clone()
	cfg1.Options.DataBroker.ClusterLeaderID = null.StringFrom("cluster1")
	cluster1.OnConfigChange(t.Context(), cfg1)

	cfg2 = cfg2.Clone()
	cfg2.Options.DataBroker.ClusterLeaderID = null.StringFrom("cluster1")
	cluster2.OnConfigChange(t.Context(), cfg2)

	_, err = client2.Put(t.Context(), &databrokerpb.PutRequest{
		Records: []*databrokerpb.Record{{
			Type: "test", Id: "record2", Data: protoutil.NewAnyString("test"),
		}},
	})
	require.NoError(t, err)

	// now cluster3 is informed

	cfg3 = cfg3.Clone()
	cfg3.Options.DataBroker.ClusterLeaderID = null.StringFrom("cluster1")
	cluster3.OnConfigChange(t.Context(), cfg3)

	select {
	case <-t.Context().Done():
		return
	case <-streamGotSecondMessage:
	}
}
