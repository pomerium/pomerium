package storage_test

import (
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"

	"github.com/pomerium/pomerium/internal/testutil"
	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/storage"
)

func TestCachingQuerier(t *testing.T) {
	t.Parallel()

	ctx := testutil.GetContext(t, time.Minute)
	cache := storage.NewGlobalCache(time.Hour)
	q1 := storage.NewStaticQuerier(&databrokerpb.Record{
		Version: 1,
		Type:    "t1",
		Id:      "r1",
	})
	q2 := storage.NewStaticQuerier(&databrokerpb.Record{
		Version: 2,
		Type:    "t1",
		Id:      "r1",
	})

	res, err := storage.NewCachingQuerier(q1, cache).Query(ctx, &databrokerpb.QueryRequest{
		Type:  "t1",
		Limit: 1,
	})
	assert.NoError(t, err)
	assert.Empty(t, cmp.Diff(&databrokerpb.QueryResponse{
		Records:       []*databrokerpb.Record{{Version: 1, Type: "t1", Id: "r1"}},
		TotalCount:    1,
		RecordVersion: 1,
	}, res, protocmp.Transform()))

	res, err = storage.NewCachingQuerier(q2, cache).Query(ctx, &databrokerpb.QueryRequest{
		Type:  "t1",
		Limit: 1,
	})
	assert.NoError(t, err)
	assert.Empty(t, cmp.Diff(&databrokerpb.QueryResponse{
		Records:       []*databrokerpb.Record{{Version: 1, Type: "t1", Id: "r1"}},
		TotalCount:    1,
		RecordVersion: 1,
	}, res, protocmp.Transform()), "should use the cached version")

	res, err = storage.NewCachingQuerier(q2, cache).Query(ctx, &databrokerpb.QueryRequest{
		Type:                     "t1",
		Limit:                    1,
		MinimumRecordVersionHint: proto.Uint64(1),
	})
	assert.NoError(t, err)
	assert.Empty(t, cmp.Diff(&databrokerpb.QueryResponse{
		Records:       []*databrokerpb.Record{{Version: 1, Type: "t1", Id: "r1"}},
		TotalCount:    1,
		RecordVersion: 1,
	}, res, protocmp.Transform()), "should use the cached version")

	res, err = storage.NewCachingQuerier(q2, cache).Query(ctx, &databrokerpb.QueryRequest{
		Type:                     "t1",
		Limit:                    1,
		MinimumRecordVersionHint: proto.Uint64(2),
	})
	assert.NoError(t, err)
	assert.Empty(t, cmp.Diff(&databrokerpb.QueryResponse{
		Records:       []*databrokerpb.Record{{Version: 2, Type: "t1", Id: "r1"}},
		TotalCount:    1,
		RecordVersion: 2,
	}, res, protocmp.Transform()), "should query the new version")
}
