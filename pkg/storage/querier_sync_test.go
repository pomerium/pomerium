package storage_test

import (
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"
	grpc "google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/pomerium/pomerium/internal/databroker"
	"github.com/pomerium/pomerium/internal/testutil"
	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/protoutil"
	"github.com/pomerium/pomerium/pkg/storage"
)

func TestSyncQuerier(t *testing.T) {
	t.Parallel()

	ctx := testutil.GetContext(t, 10*time.Minute)
	cc := testutil.NewGRPCServer(t, func(srv *grpc.Server) {
		databrokerpb.RegisterDataBrokerServiceServer(srv, databroker.New(ctx, noop.NewTracerProvider()))
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
		MinimumRecordVersionHint: proto.Uint64(res.GetRecord().GetVersion() + 1),
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
