package databroker

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	"github.com/pomerium/pomerium/internal/testutil"
)

type testSyncerHandler struct {
	getDataBrokerServiceClient func() DataBrokerServiceClient
	clearRecords               func(ctx context.Context)
	updateRecords              func(ctx context.Context, serverVersion uint64, records []*Record)
}

func (t testSyncerHandler) GetDataBrokerServiceClient() DataBrokerServiceClient {
	return t.getDataBrokerServiceClient()
}

func (t testSyncerHandler) ClearRecords(ctx context.Context) {
	t.clearRecords(ctx)
}

func (t testSyncerHandler) UpdateRecords(ctx context.Context, serverVersion uint64, records []*Record) {
	t.updateRecords(ctx, serverVersion, records)
}

type testServer struct {
	DataBrokerServiceServer
	sync       func(request *SyncRequest, server DataBrokerService_SyncServer) error
	syncLatest func(req *SyncLatestRequest, server DataBrokerService_SyncLatestServer) error
}

func (t testServer) Sync(request *SyncRequest, server DataBrokerService_SyncServer) error {
	return t.sync(request, server)
}

func (t testServer) SyncLatest(req *SyncLatestRequest, server DataBrokerService_SyncLatestServer) error {
	return t.syncLatest(req, server)
}

func TestSyncer(t *testing.T) {
	ctx := context.Background()
	ctx, clearTimeout := context.WithTimeout(ctx, time.Second*10)
	defer clearTimeout()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	lis := bufconn.Listen(1)
	r1 := &Record{Version: 1000, Id: "r1"}
	r2 := &Record{Version: 1001, Id: "r2"}
	r3 := &Record{Version: 1002, Id: "r3"}
	r5 := &Record{Version: 1004, Id: "r5"}

	syncCount := 0
	syncLatestCount := 0

	gs := grpc.NewServer()
	RegisterDataBrokerServiceServer(gs, testServer{
		sync: func(request *SyncRequest, server DataBrokerService_SyncServer) error {
			syncCount++
			switch syncCount {
			case 1:
				return status.Error(codes.Internal, "SOME INTERNAL ERROR")
			case 2:
				return status.Error(codes.Aborted, "ABORTED")
			case 3:
				_ = server.Send(&SyncResponse{
					Record: r3,
				})
				_ = server.Send(&SyncResponse{
					Record: r5,
				})
			case 4:
				select {} // block forever
			default:
				t.Fatal("unexpected call to sync", request)
			}
			return nil
		},
		syncLatest: func(_ *SyncLatestRequest, server DataBrokerService_SyncLatestServer) error {
			syncLatestCount++
			switch syncLatestCount {
			case 1:
				_ = server.Send(&SyncLatestResponse{
					Response: &SyncLatestResponse_Record{
						Record: r1,
					},
				})
				_ = server.Send(&SyncLatestResponse{
					Response: &SyncLatestResponse_Versions{
						Versions: &Versions{
							LatestRecordVersion: r1.Version,
							ServerVersion:       2000,
						},
					},
				})
			case 2:
				_ = server.Send(&SyncLatestResponse{
					Response: &SyncLatestResponse_Record{
						Record: r2,
					},
				})
				_ = server.Send(&SyncLatestResponse{
					Response: &SyncLatestResponse_Versions{
						Versions: &Versions{
							LatestRecordVersion: r2.Version,
							ServerVersion:       2001,
						},
					},
				})
			case 3:
				return status.Error(codes.Internal, "SOME INTERNAL ERROR")
			case 4:
				_ = server.Send(&SyncLatestResponse{
					Response: &SyncLatestResponse_Record{
						Record: r3,
					},
				})
				_ = server.Send(&SyncLatestResponse{
					Response: &SyncLatestResponse_Record{
						Record: r5,
					},
				})
				_ = server.Send(&SyncLatestResponse{
					Response: &SyncLatestResponse_Versions{
						Versions: &Versions{
							LatestRecordVersion: r5.Version,
							ServerVersion:       2001,
						},
					},
				})
			default:
				t.Fatal("unexpected call to sync latest")
			}
			return nil
		},
	})
	go func() { _ = gs.Serve(lis) }()

	gc, err := grpc.DialContext(ctx, "bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return lis.Dial()
		}),
		grpc.WithInsecure())
	require.NoError(t, err)
	defer func() { _ = gc.Close() }()

	clearCh := make(chan struct{})
	updateCh := make(chan []*Record)
	syncer := NewSyncer(ctx, "test", testSyncerHandler{
		getDataBrokerServiceClient: func() DataBrokerServiceClient {
			return NewDataBrokerServiceClient(gc)
		},
		clearRecords: func(_ context.Context) {
			clearCh <- struct{}{}
		},
		updateRecords: func(_ context.Context, _ uint64, records []*Record) {
			updateCh <- records
		},
	})
	go func() { _ = syncer.Run(ctx) }()

	select {
	case <-ctx.Done():
		t.Fatal("1. expected call to clear records")
	case <-clearCh:
	}

	select {
	case <-ctx.Done():
		t.Fatal("2. expected call to update records")
	case records := <-updateCh:
		testutil.AssertProtoJSONEqual(t, `[{"id": "r1", "version": "1000"}]`, records)
	}

	select {
	case <-ctx.Done():
		t.Fatal("3. expected call to clear records due to server version change")
	case <-clearCh:
	}

	select {
	case <-ctx.Done():
		t.Fatal("4. expected call to update records")
	case records := <-updateCh:
		testutil.AssertProtoJSONEqual(t, `[{"id": "r2", "version": "1001"}]`, records)
	}

	select {
	case <-ctx.Done():
		t.Fatal("5. expected call to update records from sync")
	case records := <-updateCh:
		testutil.AssertProtoJSONEqual(t, `[{"id": "r3", "version": "1002"}]`, records)
	}

	select {
	case <-ctx.Done():
		t.Fatal("6. expected call to update records")
	case records := <-updateCh:
		testutil.AssertProtoJSONEqual(t, `[{"id": "r5", "version": "1004"}]`, records)
	}

	assert.NoError(t, syncer.Close())
}
