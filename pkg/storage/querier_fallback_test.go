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

func TestFallbackQuerier(t *testing.T) {
	t.Parallel()

	ctx := testutil.GetContext(t, time.Minute)
	q1 := storage.GetQuerier(ctx) // nil querier
	q2 := storage.NewStaticQuerier(&databrokerpb.Record{
		Type:    "t1",
		Id:      "r1",
		Version: 1,
	})
	res, err := storage.NewFallbackQuerier(q1, q2).Query(ctx, &databrokerpb.QueryRequest{
		Type:  "t1",
		Limit: 1,
	})
	assert.NoError(t, err, "should fallback")
	assert.Empty(t, cmp.Diff(&databrokerpb.QueryResponse{
		Records:       []*databrokerpb.Record{{Type: "t1", Id: "r1", Version: 1}},
		TotalCount:    1,
		RecordVersion: 1,
	}, res, protocmp.Transform()))
}
