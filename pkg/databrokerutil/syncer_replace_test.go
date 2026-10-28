package databrokerutil_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	"github.com/pomerium/pomerium/pkg/databrokerutil"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
)

type testReplacingSyncerHandler struct {
	testSyncerHandler
	replaceRecords func(ctx context.Context, serverVersion uint64, records []*databroker.Record)
}

func (t testReplacingSyncerHandler) ReplaceRecords(ctx context.Context, serverVersion uint64, records []*databroker.Record) {
	t.replaceRecords(ctx, serverVersion, records)
}

// TestSyncer_ResyncReplacesRecords covers a re-sync after the server version
// changes, as it does on a databroker leader change. A handler that can
// replace its records must get the re-synced set in one call. Clearing first
// and updating after leaves the handler without records in between.
func TestSyncer_ResyncReplacesRecords(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	r1 := &databroker.Record{Version: 1000, Id: "r1"}
	serverVersions := make(chan uint64, 2)
	serverVersions <- 2000
	serverVersions <- 2001
	syncs := 0

	lis := bufconn.Listen(1024 * 1024)
	gs := grpc.NewServer()
	databroker.RegisterDataBrokerServiceServer(gs, testServer{
		sync: func(_ *databroker.SyncRequest, server databroker.DataBrokerService_SyncServer) error {
			syncs++
			if syncs == 1 {
				// the leader changed, so the server version the syncer has is stale
				return status.Error(codes.Aborted, "invalid server version")
			}
			<-server.Context().Done()
			return server.Context().Err()
		},
		syncLatest: func(_ *databroker.SyncLatestRequest, server databroker.DataBrokerService_SyncLatestServer) error {
			_ = server.Send(&databroker.SyncLatestResponse{
				Response: &databroker.SyncLatestResponse_Record{Record: r1},
			})
			_ = server.Send(&databroker.SyncLatestResponse{
				Response: &databroker.SyncLatestResponse_Versions{
					Versions: &databroker.Versions{LatestRecordVersion: r1.Version, ServerVersion: <-serverVersions},
				},
			})
			return nil
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

	calls := make(chan string, 16)
	replaced := make(chan uint64, 2)
	syncer := databrokerutil.NewSyncer(ctx, "test", testReplacingSyncerHandler{
		testSyncerHandler: testSyncerHandler{
			getDataBrokerServiceClient: func() databroker.DataBrokerServiceClient {
				return databroker.NewDataBrokerServiceClient(cc)
			},
			clearRecords: func(context.Context) {
				calls <- "ClearRecords"
			},
			updateRecords: func(context.Context, uint64, []*databroker.Record) {
				calls <- "UpdateRecords"
			},
		},
		replaceRecords: func(_ context.Context, serverVersion uint64, records []*databroker.Record) {
			calls <- "ReplaceRecords"
			if assert.Len(t, records, 1) {
				assert.Equal(t, "r1", records[0].GetId())
			}
			replaced <- serverVersion
		},
	})
	go func() { _ = syncer.Run(ctx) }()

	// the initial sync and the re-sync after the leader change
	var got []string
	for len(got) < 4 && !assert.ObjectsAreEqual([]string{"ReplaceRecords", "ReplaceRecords"}, got) {
		select {
		case <-ctx.Done():
			t.Fatalf("handler calls so far: %v", got)
		case call := <-calls:
			got = append(got, call)
		}
	}
	require.Equal(t, []string{"ReplaceRecords", "ReplaceRecords"}, got,
		"the syncer cleared the handler's records before delivering the re-synced ones")
	assert.Equal(t, uint64(2000), <-replaced)
	assert.Equal(t, uint64(2001), <-replaced)
}
