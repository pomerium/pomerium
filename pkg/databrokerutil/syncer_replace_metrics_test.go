package databrokerutil_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	"github.com/pomerium/pomerium/pkg/databrokerutil"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
)

// TestSyncer_ReplaceRecordsCountsClear covers the initial sync of a handler
// that replaces its records. The syncer must still count the clear in
// databroker.syncer.clear_records.total, as it does for a handler that is
// cleared and then updated.
func TestSyncer_ReplaceRecordsCountsClear(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	lis := bufconn.Listen(1024 * 1024)
	gs := grpc.NewServer()
	databroker.RegisterDataBrokerServiceServer(gs, testServer{
		sync: func(_ *databroker.SyncRequest, server databroker.DataBrokerService_SyncServer) error {
			<-server.Context().Done()
			return server.Context().Err()
		},
		syncLatest: func(_ *databroker.SyncLatestRequest, server databroker.DataBrokerService_SyncLatestServer) error {
			return server.Send(&databroker.SyncLatestResponse{
				Response: &databroker.SyncLatestResponse_Versions{
					Versions: &databroker.Versions{LatestRecordVersion: 1, ServerVersion: 2000},
				},
			})
		},
	})
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)

	cc, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return lis.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = cc.Close() })

	reader := sdkmetric.NewManualReader()
	m, err := databrokerutil.NewSyncerMetrics(sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)).Meter("test"))
	require.NoError(t, err)

	replaced := make(chan struct{}, 1)
	syncer := databrokerutil.NewSyncer(ctx, "test", testReplacingSyncerHandler{
		testSyncerHandler: testSyncerHandler{
			getDataBrokerServiceClient: func() databroker.DataBrokerServiceClient {
				return databroker.NewDataBrokerServiceClient(cc)
			},
			clearRecords:  func(context.Context) {},
			updateRecords: func(context.Context, uint64, []*databroker.Record) {},
		},
		replaceRecords: func(context.Context, uint64, []*databroker.Record) {
			replaced <- struct{}{}
		},
	}, databrokerutil.WithSyncerMetrics(m))
	go func() { _ = syncer.Run(ctx) }()

	select {
	case <-ctx.Done():
		t.Fatal("the handler's records were never replaced")
	case <-replaced:
	}

	// the replace runs before the syncer records its metrics
	assert.Eventually(t, func() bool {
		return clearRecordsTotal(t, reader) == 1
	}, 2*time.Second, 10*time.Millisecond, "databroker.syncer.clear_records.total = %d", clearRecordsTotal(t, reader))
}

func clearRecordsTotal(t *testing.T, reader sdkmetric.Reader) int64 {
	t.Helper()

	var rm metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(t.Context(), &rm))
	var total int64
	for _, sm := range rm.ScopeMetrics {
		for _, mt := range sm.Metrics {
			if mt.Name != "databroker.syncer.clear_records.total" {
				continue
			}
			for _, dp := range mt.Data.(metricdata.Sum[int64]).DataPoints {
				total += dp.Value
			}
		}
	}
	return total
}
