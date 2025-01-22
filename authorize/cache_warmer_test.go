package authorize

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/grpc"

	"github.com/pomerium/pomerium/internal/databroker"
	"github.com/pomerium/pomerium/internal/testutil"
	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/protoutil"
	"github.com/pomerium/pomerium/pkg/storage"
)

func TestCacheWarmer(t *testing.T) {
	t.Parallel()

	ctx := testutil.GetContext(t, 10*time.Minute)
	cc := testutil.NewGRPCServer(t, func(srv *grpc.Server) {
		databrokerpb.RegisterDataBrokerServiceServer(srv, databroker.New(ctx, noop.NewTracerProvider()))
	})
	t.Cleanup(func() { cc.Close() })

	client := databrokerpb.NewDataBrokerServiceClient(cc)
	_, err := client.Put(ctx, &databrokerpb.PutRequest{
		Records: []*databrokerpb.Record{
			{Type: "example.com/record", Id: "e1", Data: protoutil.NewAnyBool(true)},
			{Type: "example.com/record", Id: "e2", Data: protoutil.NewAnyBool(true)},
		},
	})
	require.NoError(t, err)

	cache := storage.NewGlobalCache(time.Minute)

	cw := newCacheWarmer(cc, cache, "example.com/record")
	go cw.Run(ctx)

	assert.Eventually(t, func() bool {
		req := &databrokerpb.QueryRequest{
			Type:  "example.com/record",
			Limit: 1,
		}
		req.SetFilterByIDOrIndex("e1")
		res, err := storage.NewCachingQuerier(storage.NewStaticQuerier(), cache).Query(ctx, req)
		require.NoError(t, err)
		return len(res.GetRecords()) == 1
	}, 10*time.Second, time.Millisecond*100)
}
