package storage_test

import (
	"io"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"
	"go.uber.org/mock/gomock"
	grpc "google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/pomerium/pomerium/internal/databroker"
	"github.com/pomerium/pomerium/internal/testutil"
	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/databroker/mock_databroker"
	"github.com/pomerium/pomerium/pkg/protoutil"
	"github.com/pomerium/pomerium/pkg/storage"
)

func TestSyncQuerier(t *testing.T) {
	t.Parallel()

	ctx := testutil.GetContext(t, 10*time.Minute)

	srv := databroker.NewBackendServer(noop.NewTracerProvider())
	t.Cleanup(srv.Stop)

	cc := testutil.NewGRPCServer(t, func(s *grpc.Server) {
		databrokerpb.RegisterDataBrokerServiceServer(s, srv)
	})
	t.Cleanup(func() { cc.Close() })

	client := databrokerpb.NewDataBrokerServiceClient(cc)

	r1 := &databrokerpb.Record{
		Type: "t1",
		Id:   "r1",
		Data: protoutil.ToAny("q2"),
	}
	_, err := client.Put(ctx, &databrokerpb.PutRequest{
		Records: []*databrokerpb.Record{r1},
	})
	require.NoError(t, err)

	r2 := &databrokerpb.Record{
		Type: "t1",
		Id:   "r2",
		Data: protoutil.ToAny("q2"),
	}

	r2a := &databrokerpb.Record{
		Type: "t1",
		Id:   "r2",
		Data: protoutil.ToAny("q2a"),
	}

	q := storage.NewSyncQuerier(client, "t1")
	t.Cleanup(q.Stop)

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		res, err := q.Query(ctx, &databrokerpb.QueryRequest{
			Type: "t1",
			Filter: newStruct(t, map[string]any{
				"id": "r1",
			}),
			Limit: 1,
		})
		if assert.NoError(c, err) && assert.Len(c, res.Records, 1) {
			assert.Empty(c, cmp.Diff(r1.Data, res.Records[0].Data, protocmp.Transform()))
		}
	}, time.Second*10, time.Millisecond*50, "should sync records")

	res, err := client.Put(ctx, &databrokerpb.PutRequest{
		Records: []*databrokerpb.Record{r2},
	})
	require.NoError(t, err)

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		res, err := q.Query(ctx, &databrokerpb.QueryRequest{
			Type: "t1",
			Filter: newStruct(t, map[string]any{
				"id": "r2",
			}),
			Limit: 1,
		})
		if assert.NoError(c, err) && assert.Len(c, res.Records, 1) {
			assert.Empty(c, cmp.Diff(r2.Data, res.Records[0].Data, protocmp.Transform()))
		}
	}, time.Second*10, time.Millisecond*50, "should pick up changes")

	q.InvalidateCache(ctx, &databrokerpb.QueryRequest{
		Type:                     "t1",
		MinimumRecordVersionHint: new(res.GetRecord().GetVersion() + 1),
	})

	_, err = q.Query(ctx, &databrokerpb.QueryRequest{
		Type: "t1",
		Filter: newStruct(t, map[string]any{
			"id": "r2",
		}),
		Limit: 1,
	})
	assert.ErrorIs(t, err, storage.ErrUnavailable,
		"should return unavailable until record is updated")

	res, err = client.Put(ctx, &databrokerpb.PutRequest{
		Records: []*databrokerpb.Record{r2a},
	})
	require.NoError(t, err)

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		res, err := q.Query(ctx, &databrokerpb.QueryRequest{
			Type: "t1",
			Filter: newStruct(t, map[string]any{
				"id": "r2",
			}),
			Limit: 1,
		})
		if assert.NoError(c, err) && assert.Len(c, res.Records, 1) {
			assert.Empty(c, cmp.Diff(r2a.Data, res.Records[0].Data, protocmp.Transform()))
		}
	}, time.Second*10, time.Millisecond*50, "should pick up changes after invalidation")
}

func newStruct(t *testing.T, m map[string]any) *structpb.Struct {
	t.Helper()
	s, err := structpb.NewStruct(m)
	require.NoError(t, err)
	return s
}

func TestSyncQuerierCancellable(t *testing.T) {
	t.Parallel()

	ctx := testutil.GetContext(t, 10*time.Minute)
	srv := databroker.NewBackendServer(noop.NewTracerProvider())

	t.Cleanup(srv.Stop)

	cc := testutil.NewGRPCServer(t, func(s *grpc.Server) {
		databrokerpb.RegisterDataBrokerServiceServer(s, srv)
	})

	t.Cleanup(func() { cc.Close() })

	client := databrokerpb.NewDataBrokerServiceClient(cc)

	r1 := &databrokerpb.Record{
		Type: "foo",
		Id:   "k1",
		Data: protoutil.ToAny("v2"),
	}
	_, err := client.Put(ctx, &databrokerpb.PutRequest{
		Records: []*databrokerpb.Record{r1},
	})
	require.NoError(t, err)

	r2 := &databrokerpb.Record{
		Type: "foo",
		Id:   "k2",
		Data: protoutil.ToAny("v2"),
	}

	q := storage.NewSyncQuerier(client, "foo")

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		res, err := q.Query(ctx, &databrokerpb.QueryRequest{
			Type: "foo",
			Filter: newStruct(t, map[string]any{
				"id": "k1",
			}),
			Limit: 1,
		})
		if assert.NoError(c, err) && assert.Len(c, res.Records, 1) {
			assert.Empty(c, cmp.Diff(r1.Data, res.Records[0].Data, protocmp.Transform()))
		}
	}, time.Second*10, time.Millisecond*50, "caching querier should pick up changes")

	q.Stop()

	_, err = client.Put(ctx, &databrokerpb.PutRequest{
		Records: []*databrokerpb.Record{r2},
	})
	require.NoError(t, err)

	testutil.AssertConsistentlyWithT(t, func(c assert.TestingT) {
		res, err := q.Query(ctx, &databrokerpb.QueryRequest{
			Type: "foo",
			Filter: newStruct(t, map[string]any{
				"id": "k2",
			}),
		})
		assert.Nil(c, err)
		assert.NotNil(c, res)
		assert.Len(c, res.Records, 0)
	}, time.Second, time.Millisecond*50, "caching querier is expected not pick up changes")
}

func TestSyncQuerierRemoteAborted(t *testing.T) {
	t.Parallel()

	ctx := testutil.GetContext(t, 10*time.Minute)
	ctrl := gomock.NewController(t)
	mockClient := mock_databroker.NewMockDataBrokerServiceClient(ctrl)
	mockSyncLatestStream := mock_databroker.NewMockSyncLatestClient(ctrl)
	mockSyncStream := mock_databroker.NewMockSyncClient(ctrl)

	r1 := &databrokerpb.Record{
		Type:    "foo",
		Id:      "k1",
		Version: 1,
		Data:    protoutil.ToAny("v1"),
	}

	mockSyncLatestStream.EXPECT().Recv().Return(&databrokerpb.SyncLatestResponse{
		Response: &databrokerpb.SyncLatestResponse_Record{Record: r1},
	}, nil)
	mockSyncLatestStream.EXPECT().Recv().Return(&databrokerpb.SyncLatestResponse{
		Response: &databrokerpb.SyncLatestResponse_Versions{
			Versions: &databrokerpb.Versions{
				ServerVersion:       1,
				LatestRecordVersion: 1,
			},
		},
	}, nil)
	mockSyncLatestStream.EXPECT().Recv().Return(nil, io.EOF)

	mockClient.EXPECT().SyncLatest(gomock.Any(), gomock.Any()).Return(mockSyncLatestStream, nil)
	mockClient.EXPECT().Sync(gomock.Any(), gomock.Any()).Return(mockSyncStream, nil)
	// simulate when databroker leader / follower reset occurs
	// and we should fetch latest records again
	mockSyncStream.EXPECT().Recv().Return(nil, status.Error(codes.Aborted, "aborted"))

	// transport error
	mockClient.EXPECT().SyncLatest(gomock.Any(), gomock.Any()).Return(nil, io.EOF).AnyTimes()

	q := storage.NewSyncQuerier(mockClient, "foo")
	t.Cleanup(q.Stop)

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		_, err := q.Query(ctx, &databrokerpb.QueryRequest{
			Type: "foo",
			Filter: newStruct(t, map[string]any{
				"id": "k1",
			}),
			Limit: 1,
		})
		assert.Error(c, err)
		assert.ErrorIs(c, err, storage.ErrUnavailable)
	}, time.Second*10, time.Millisecond*50, "should return error after aborted reset")
}

func TestSyncQuerierRemoteClose(t *testing.T) {
	t.Parallel()

	ctx := testutil.GetContext(t, 10*time.Minute)
	ctrl := gomock.NewController(t)

	mockClient := mock_databroker.NewMockDataBrokerServiceClient(ctrl)
	mockSyncLatestStream := mock_databroker.NewMockSyncLatestClient(ctrl)
	mockSyncStream := mock_databroker.NewMockSyncClient(ctrl)

	r1 := &databrokerpb.Record{
		Type:    "foo",
		Id:      "k1",
		Version: 1,
		Data:    protoutil.ToAny("v1"),
	}

	mockSyncLatestStream.EXPECT().Recv().Return(&databrokerpb.SyncLatestResponse{
		Response: &databrokerpb.SyncLatestResponse_Record{Record: r1},
	}, nil)
	mockSyncLatestStream.EXPECT().Recv().Return(&databrokerpb.SyncLatestResponse{
		Response: &databrokerpb.SyncLatestResponse_Versions{
			Versions: &databrokerpb.Versions{
				ServerVersion:       1,
				LatestRecordVersion: 1,
			},
		},
	}, nil)
	mockSyncLatestStream.EXPECT().Recv().Return(nil, io.EOF)
	mockClient.EXPECT().SyncLatest(gomock.Any(), gomock.Any()).Return(mockSyncLatestStream, nil)

	// simulate remote servers closing with transport errors, most common one is : io.EOF
	mockSyncStream.EXPECT().Recv().Return(nil, io.EOF).AnyTimes()
	mockClient.EXPECT().Sync(gomock.Any(), gomock.Any()).Return(mockSyncStream, nil).AnyTimes()
	mockClient.EXPECT().SyncLatest(gomock.Any(), gomock.Any()).Return(nil, io.EOF).AnyTimes()

	q := storage.NewSyncQuerier(mockClient, "foo")
	t.Cleanup(q.Stop)

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		res, err := q.Query(ctx, &databrokerpb.QueryRequest{
			Type: "foo",
			Filter: newStruct(t, map[string]any{
				"id": "k1",
			}),
			Limit: 1,
		})
		if assert.NoError(c, err) && assert.Len(c, res.Records, 1) {
			assert.Empty(c, cmp.Diff(r1.Data, res.Records[0].Data, protocmp.Transform()))
		}
	}, time.Second*10, time.Millisecond*50, "should sync initial records")

	// caching querier should still serve data it is known to have
	testutil.AssertConsistentlyWithT(t, func(c assert.TestingT) {
		res, err := q.Query(ctx, &databrokerpb.QueryRequest{
			Type: "foo",
			Filter: newStruct(t, map[string]any{
				"id": "k1",
			}),
			Limit: 1,
		})
		assert.NoError(c, err)
		assert.Len(c, res.GetRecords(), 1)
		assert.Empty(c, cmp.Diff(r1.Data, res.GetRecords()[0].Data, protocmp.Transform()))
	}, time.Second, 50*time.Millisecond)
}

func TestRetriesOnCanceled(t *testing.T) {
	// Previously, if a stream returned a Canceled error code, we would stop
	// retrying requests. Since the clustered databroker cancels streams when
	// leadership changes, this resulted in sessions never being updated.
	//
	// This test ensures that merely receiving codes.Canceled will not stop
	// retries. Instead .Stop should be called on the sync querier.

	t.Parallel()

	ctrl := gomock.NewController(t)
	mockClient := mock_databroker.NewMockDataBrokerServiceClient(ctrl)

	var callCount atomic.Uint64
	mockSyncLatestStream := mock_databroker.NewMockSyncLatestClient(ctrl)
	mockSyncLatestStream.EXPECT().Recv().AnyTimes().DoAndReturn(func() (*databrokerpb.SyncLatestResponse, error) {
		callCount.Add(1)
		return nil, status.Error(codes.Canceled, "test-canceled")
	})
	mockClient.EXPECT().SyncLatest(gomock.Any(), gomock.Any()).AnyTimes().Return(mockSyncLatestStream, nil)

	q := storage.NewSyncQuerier(mockClient, "t1")
	t.Cleanup(q.Stop)

	assert.Eventually(t, func() bool { return callCount.Load() > 1 }, 10*time.Second, 10*time.Millisecond,
		"should retry canceled errors")
}
