package databroker_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/volatiletech/null/v9"
	"go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/databroker"
	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpcutil"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

var testSharedKey = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x01}, 32))

func newTestConfig(opts config.DataBrokerOptions) *config.Config {
	return &config.Config{
		Options: &config.Options{
			SharedKey:  testSharedKey,
			DataBroker: opts,
		},
	}
}

func clusteredConfig(nodeID, leaderID string, nodes config.DataBrokerClusterNodes) *config.Config {
	return newTestConfig(config.DataBrokerOptions{
		ClusterNodeID:   null.StringFrom(nodeID),
		ClusterLeaderID: null.StringFrom(leaderID),
		ClusterNodes:    nodes,
	})
}

func newGRPCServer(t *testing.T, register func(s *grpc.Server)) string {
	t.Helper()
	li, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	s := grpc.NewServer()
	register(s)
	go func() { _ = s.Serve(li) }()
	t.Cleanup(s.Stop)
	return "http://" + li.Addr().String()
}

func clusterDefinition(idA, addrA, idB, addrB string, additionalNodes ...string) config.DataBrokerClusterNodes {
	base := config.DataBrokerClusterNodes{
		{ID: idA, GRPCAddress: addrA},
		{ID: idB, GRPCAddress: addrB},
	}

	if len(additionalNodes) == 0 {
		return base
	}
	if len(additionalNodes)%2 == 1 {
		panic("extra nodes must specify (id, addr) pairs")
	}
	for i := 0; i < len(additionalNodes); i += 2 {
		base = append(base, config.DataBrokerClusterNode{
			ID:          additionalNodes[i],
			GRPCAddress: additionalNodes[i+1],
		})
	}
	return base
}

func TestClusteredServer(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	tp := noop.NewTracerProvider()

	backendA := databroker.NewBackendServer(tp)
	t.Cleanup(backendA.Stop)
	addrA := newGRPCServer(t, func(s *grpc.Server) {
		databrokerpb.RegisterDataBrokerServiceServer(s, backendA)
	})

	backendB := databroker.NewBackendServer(tp)
	t.Cleanup(backendB.Stop)
	addrB := newGRPCServer(t, func(s *grpc.Server) {
		databrokerpb.RegisterDataBrokerServiceServer(s, backendB)
	})

	sharedKeyBytes, err := base64.StdEncoding.DecodeString(testSharedKey)
	require.NoError(t, err)
	getKey := func() []byte { return sharedKeyBytes }

	dialOpts := []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithChainUnaryInterceptor(grpcutil.WithUnarySignedJWT(getKey)),
		grpc.WithChainStreamInterceptor(grpcutil.WithStreamSignedJWT(getKey)),
	}

	ccA, err := grpc.NewClient(strings.TrimPrefix(addrA, "http://"), dialOpts...)
	require.NoError(t, err)
	t.Cleanup(func() { ccA.Close() })

	ccB, err := grpc.NewClient(strings.TrimPrefix(addrB, "http://"), dialOpts...)
	require.NoError(t, err)
	t.Cleanup(func() { ccB.Close() })

	nodes := clusterDefinition("a", addrA, "b", addrB)

	srvA := databroker.NewClusteredServer(tp, backendA, clusteredConfig("a", "a", nodes))
	t.Cleanup(srvA.Stop)
	srvB := databroker.NewClusteredServer(tp, backendB, clusteredConfig("b", "a", nodes))
	t.Cleanup(srvB.Stop)

	t.Run("leader swap sync should behave", func(t *testing.T) {
		_, err := srvA.Put(ctx, &databrokerpb.PutRequest{
			Records: []*databrokerpb.Record{
				{
					Version: 1,
					Type:    "foo",
					Id:      "foo",
					Data:    protoutil.ToAny("foo"),
				},
			},
		})
		require.NoError(t, err)
		bo := backoff.NewExponentialBackOff(
			backoff.WithInitialInterval(10*time.Millisecond),
			backoff.WithMultiplier(1.0),
			backoff.WithMaxElapsedTime(100*time.Millisecond),
		)

		testHandlerA := &testSyncerHandler{
			recordMu: sync.RWMutex{},
			records:  map[string]*databrokerpb.Record{},
			client:   databrokerpb.NewDataBrokerServiceClient(ccA),
		}
		testHandlerB := &testSyncerHandler{
			recordMu: sync.RWMutex{},
			records:  map[string]*databrokerpb.Record{},
			client:   databrokerpb.NewDataBrokerServiceClient(ccB),
		}
		syncA := databrokerpb.NewSyncer(ctx, "syncer-a", testHandlerA, databrokerpb.WithBackOff(bo))
		syncB := databrokerpb.NewSyncer(ctx, "syncer-b", testHandlerB, databrokerpb.WithBackOff(bo))

		go syncA.Run(ctx)
		go syncB.Run(ctx)
		t.Cleanup(func() {
			_ = syncA.Close()
		})
		t.Cleanup(func() {
			_ = syncB.Close()
		})

		for i := range 100 {
			var leaderId string
			if i%2 == 0 {
				leaderId = "a"
			} else {
				leaderId = "b"
			}

			wg := sync.WaitGroup{}
			wg.Go(func() {
				srvA.OnConfigChange(t.Context(), clusteredConfig("a", leaderId, nodes))
			})
			wg.Go(func() {
				srvB.OnConfigChange(t.Context(), clusteredConfig("a", leaderId, nodes))
			})
			wg.Wait()
		}
		t.Log("done swapping leaders")

		assert.Eventually(t, func() bool {
			testHandlerA.recordMu.RLock()
			testHandlerB.recordMu.RLock()
			defer testHandlerA.recordMu.RUnlock()
			defer testHandlerB.recordMu.RUnlock()
			return len(testHandlerA.records) == 1 && len(testHandlerB.records) == 1
		}, time.Second*100, time.Millisecond*50)
	})
}

type testSyncerHandler struct {
	recordMu sync.RWMutex
	records  map[string]*databrokerpb.Record
	client   databrokerpb.DataBrokerServiceClient
}

var _ databrokerpb.SyncerHandler = (*testSyncerHandler)(nil)

func (t *testSyncerHandler) ClearRecords(_ context.Context) {
	t.recordMu.Lock()
	t.records = map[string]*databrokerpb.Record{}
	t.recordMu.Unlock()
}

func (t *testSyncerHandler) GetDataBrokerServiceClient() databrokerpb.DataBrokerServiceClient {
	return t.client
}

func (t *testSyncerHandler) UpdateRecords(_ context.Context, _ uint64, records []*databrokerpb.Record) {
	t.recordMu.Lock()
	defer t.recordMu.Unlock()

	for _, rec := range records {
		t.records[rec.GetId()] = rec
	}
}
