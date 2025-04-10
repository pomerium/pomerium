package storage_test

import (
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/testing/protocmp"

	"github.com/pomerium/pomerium/internal/testutil"
	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/storage"
)

func TestTypedQuerier(t *testing.T) {
	t.Parallel()

	ctx := testutil.GetContext(t, time.Minute)

	q1 := storage.NewStaticQuerier(&databrokerpb.Record{
		Type: "t1",
		Id:   "r1",
	})
	q2 := storage.NewStaticQuerier(&databrokerpb.Record{
		Type: "t2",
		Id:   "r2",
	})
	q3 := storage.NewStaticQuerier(&databrokerpb.Record{
		Type: "t3",
		Id:   "r3",
	})

	q := storage.NewTypedQuerier(q1, map[string]storage.Querier{
		"t2": q2,
		"t3": q3,
	})

	res, err := q.Query(ctx, &databrokerpb.QueryRequest{
		Type:  "t1",
		Limit: 1,
	})
	assert.NoError(t, err)
	assert.Empty(t, cmp.Diff(&databrokerpb.QueryResponse{
		Records:    []*databrokerpb.Record{{Type: "t1", Id: "r1"}},
		TotalCount: 1,
	}, res, protocmp.Transform()))

	res, err = q.Query(ctx, &databrokerpb.QueryRequest{
		Type:  "t2",
		Limit: 1,
	})
	assert.NoError(t, err)
	assert.Empty(t, cmp.Diff(&databrokerpb.QueryResponse{
		Records:    []*databrokerpb.Record{{Type: "t2", Id: "r2"}},
		TotalCount: 1,
	}, res, protocmp.Transform()))

	res, err = q.Query(ctx, &databrokerpb.QueryRequest{
		Type:  "t3",
		Limit: 1,
	})
	assert.NoError(t, err)
	assert.Empty(t, cmp.Diff(&databrokerpb.QueryResponse{
		Records:    []*databrokerpb.Record{{Type: "t3", Id: "r3"}},
		TotalCount: 1,
	}, res, protocmp.Transform()))
}
