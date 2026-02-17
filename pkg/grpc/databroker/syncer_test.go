package databroker_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	"github.com/pomerium/pomerium/internal/testutil"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/databroker/mock_databroker"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

type testSyncerHandler struct {
	getDataBrokerServiceClient func() databroker.DataBrokerServiceClient
	clearRecords               func(ctx context.Context)
	updateRecords              func(ctx context.Context, serverVersion uint64, records []*databroker.Record)
}

func (t testSyncerHandler) GetDataBrokerServiceClient() databroker.DataBrokerServiceClient {
	return t.getDataBrokerServiceClient()
}

func (t testSyncerHandler) ClearRecords(ctx context.Context) {
	t.clearRecords(ctx)
}

func (t testSyncerHandler) UpdateRecords(ctx context.Context, serverVersion uint64, records []*databroker.Record) {
	t.updateRecords(ctx, serverVersion, records)
}

type testServer struct {
	databroker.DataBrokerServiceServer
	sync       func(request *databroker.SyncRequest, server databroker.DataBrokerService_SyncServer) error
	syncLatest func(req *databroker.SyncLatestRequest, server databroker.DataBrokerService_SyncLatestServer) error
}

func (t testServer) Sync(request *databroker.SyncRequest, server databroker.DataBrokerService_SyncServer) error {
	return t.sync(request, server)
}

func (t testServer) SyncLatest(req *databroker.SyncLatestRequest, server databroker.DataBrokerService_SyncLatestServer) error {
	return t.syncLatest(req, server)
}

func TestSyncer(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	ctx, clearTimeout := context.WithTimeout(ctx, time.Second*10)
	defer clearTimeout()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	lis := bufconn.Listen(1)
	r1 := &databroker.Record{Version: 1000, Id: "r1"}
	r2 := &databroker.Record{Version: 1001, Id: "r2"}
	r3 := &databroker.Record{Version: 1002, Id: "r3"}
	r5 := &databroker.Record{Version: 1004, Id: "r5"}

	syncCount := 0
	syncLatestCount := 0

	gs := grpc.NewServer()
	databroker.RegisterDataBrokerServiceServer(gs, testServer{
		sync: func(request *databroker.SyncRequest, server databroker.DataBrokerService_SyncServer) error {
			syncCount++
			switch syncCount {
			case 1:
				return status.Error(codes.Internal, "SOME INTERNAL ERROR")
			case 2:
				return status.Error(codes.Aborted, "ABORTED")
			case 3:
				_ = server.Send(&databroker.SyncResponse{
					Response: &databroker.SyncResponse_Record{
						Record: r3,
					},
				})
				_ = server.Send(&databroker.SyncResponse{
					Response: &databroker.SyncResponse_Record{
						Record: r5,
					},
				})
			case 4:
				select {} // block forever
			default:
				t.Fatal("unexpected call to sync", request)
			}
			return nil
		},
		syncLatest: func(_ *databroker.SyncLatestRequest, server databroker.DataBrokerService_SyncLatestServer) error {
			syncLatestCount++
			switch syncLatestCount {
			case 1:
				_ = server.Send(&databroker.SyncLatestResponse{
					Response: &databroker.SyncLatestResponse_Record{
						Record: r1,
					},
				})
				_ = server.Send(&databroker.SyncLatestResponse{
					Response: &databroker.SyncLatestResponse_Versions{
						Versions: &databroker.Versions{
							LatestRecordVersion: r1.Version,
							ServerVersion:       2000,
						},
					},
				})
			case 2:
				_ = server.Send(&databroker.SyncLatestResponse{
					Response: &databroker.SyncLatestResponse_Record{
						Record: r2,
					},
				})
				_ = server.Send(&databroker.SyncLatestResponse{
					Response: &databroker.SyncLatestResponse_Versions{
						Versions: &databroker.Versions{
							LatestRecordVersion: r2.Version,
							ServerVersion:       2001,
						},
					},
				})
			case 3:
				return status.Error(codes.Internal, "SOME INTERNAL ERROR")
			case 4:
				_ = server.Send(&databroker.SyncLatestResponse{
					Response: &databroker.SyncLatestResponse_Record{
						Record: r3,
					},
				})
				_ = server.Send(&databroker.SyncLatestResponse{
					Response: &databroker.SyncLatestResponse_Record{
						Record: r5,
					},
				})
				_ = server.Send(&databroker.SyncLatestResponse{
					Response: &databroker.SyncLatestResponse_Versions{
						Versions: &databroker.Versions{
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
	updateCh := make(chan []*databroker.Record)
	syncer := databroker.NewSyncer(ctx, "test", testSyncerHandler{
		getDataBrokerServiceClient: func() databroker.DataBrokerServiceClient {
			return databroker.NewDataBrokerServiceClient(gc)
		},
		clearRecords: func(_ context.Context) {
			clearCh <- struct{}{}
		},
		updateRecords: func(_ context.Context, _ uint64, records []*databroker.Record) {
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

func TestSyncerOnTransientErrors(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)

	mockClient := mock_databroker.NewMockDataBrokerServiceClient(ctrl)
	mockSyncStream := mock_databroker.NewMockSyncClient(ctrl)
	mockSyncLatestStream := mock_databroker.NewMockSyncLatestClient(ctrl)

	makeOneRecord := func(n int) *databroker.Record {
		return &databrokerpb.Record{
			Type:    "foo",
			Id:      fmt.Sprintf("k%d", n),
			Version: uint64(n),
			Data:    protoutil.ToAny(fmt.Sprintf("v%d", n)),
		}
	}

	makeRecordMap := func(n int) map[string]*databrokerpb.Record {
		ret := make(map[string]*databrokerpb.Record)

		for i := range n {
			rec := makeOneRecord(i)
			ret[rec.GetId()] = rec
		}
		return ret
	}

	sendSyncLatestStreamN := func(n int) {
		for i := range n {
			mockSyncLatestStream.EXPECT().Recv().Return(&databrokerpb.SyncLatestResponse{
				Response: &databrokerpb.SyncLatestResponse_Record{Record: makeOneRecord(i)},
			}, nil)
		}

		mockSyncLatestStream.EXPECT().Recv().Return(&databrokerpb.SyncLatestResponse{
			Response: &databrokerpb.SyncLatestResponse_Versions{
				Versions: &databrokerpb.Versions{
					ServerVersion:       1,
					LatestRecordVersion: uint64(n),
				},
			},
		}, nil)
		mockSyncLatestStream.EXPECT().Recv().Return(nil, io.EOF)
	}

	sendSyncStreamN := func(start, end int) {
		for i := start; i < end; i++ {
			mockSyncStream.EXPECT().Recv().Return(&databroker.SyncResponse{
				Response: &databrokerpb.SyncResponse_Record{Record: makeOneRecord(i)},
			}, nil)
		}
	}

	setStreamErrResponse := func(err error) {
		mockSyncStream.EXPECT().Recv().Return(nil, err)
	}

	setSyncLatestValid := func() {
		mockClient.EXPECT().SyncLatest(gomock.Any(), gomock.Any()).Return(mockSyncLatestStream, nil)
	}
	setSyncValid := func() {
		mockClient.EXPECT().Sync(gomock.Any(), gomock.Any()).Return(mockSyncStream, nil)
	}

	setSyncLatestTransportError := func(err error) {
		mockClient.EXPECT().SyncLatest(gomock.Any(), gomock.Any()).Return(nil, err)
	}

	setSyncTransportError := func(err error) {
		mockClient.EXPECT().Sync(gomock.Any(), gomock.Any()).Return(nil, err)
	}

	// The syncer flow:
	// 1. serverVersion=0 -> calls SyncLatest (init)
	// 2. serverVersion!=0 -> calls Sync
	// 3. Only codes.Aborted resets serverVersion to 0, triggering re-init
	// 4. Other errors (Canceled, transport errors) just retry the current operation

	// Step 1: Initial SyncLatest returns records k0, k1
	setSyncLatestValid()
	sendSyncLatestStreamN(2)

	// Step 2: Sync returns k2, then Canceled error
	setSyncValid()
	sendSyncStreamN(2, 3)
	setStreamErrResponse(status.Error(codes.Canceled, "cancelled"))

	// Step 3: Canceled doesn't reset serverVersion, so Sync is retried (not SyncLatest)
	// Sync transport error
	setSyncTransportError(io.EOF)

	// Step 4: Retry Sync, returns k3, k4, k5, then Aborted error
	setSyncValid()
	sendSyncStreamN(3, 6)
	setStreamErrResponse(status.Error(codes.Aborted, "aborted"))

	// Step 5: Aborted resets serverVersion, so SyncLatest is called
	// SyncLatest transport error
	setSyncLatestTransportError(io.EOF)

	// Step 6: Retry SyncLatest, returns all 6 records
	setSyncLatestValid()
	sendSyncLatestStreamN(6)

	// Step 7: Sync is called. We need to handle retries to avoid gomock errors.
	// Use AnyTimes() so the test can complete gracefully.
	mockClient.EXPECT().Sync(gomock.Any(), gomock.Any()).Return(mockSyncStream, nil).AnyTimes()
	mockSyncStream.EXPECT().Recv().Return(nil, io.EOF).AnyTimes()

	ctx, ca := context.WithCancel(t.Context())
	defer ca()

	mu := sync.Mutex{}

	serverVersionT := uint64(0)
	recordMap := map[string]*databrokerpb.Record{}
	testHandler := testSyncerHandler{
		getDataBrokerServiceClient: func() databrokerpb.DataBrokerServiceClient {
			return mockClient
		},
		clearRecords: func(_ context.Context) {
			mu.Lock()
			defer mu.Unlock()
			recordMap = map[string]*databrokerpb.Record{}
		},
		updateRecords: func(_ context.Context, serverVersion uint64, records []*databrokerpb.Record) {
			mu.Lock()
			defer mu.Unlock()
			for _, rec := range records {
				recordMap[rec.GetId()] = rec
			}
			serverVersionT = serverVersion
		},
	}

	bo := backoff.NewExponentialBackOff(
		backoff.WithInitialInterval(10*time.Millisecond),
		backoff.WithMultiplier(1.0),
		backoff.WithMaxElapsedTime(100*time.Millisecond),
	)
	bo.MaxElapsedTime = 0

	syncer := databrokerpb.NewSyncer(ctx, "foo-syncer", testHandler, databroker.WithBackOff(bo))
	go syncer.Run(ctx)

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		mu.Lock()
		defer mu.Unlock()
		assert.Equal(c, uint64(1), serverVersionT)
	}, time.Second, time.Millisecond*50)

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		mu.Lock()
		defer mu.Unlock()
		assert.Equal(c, makeRecordMap(6), recordMap)
	}, time.Second*3, time.Millisecond*50)
}
