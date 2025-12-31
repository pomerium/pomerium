package storage_test

import (
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"
	grpc "google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/testing/protocmp"

	"github.com/pomerium/pomerium/internal/databroker"
	"github.com/pomerium/pomerium/internal/testutil"
	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/storage"
)

func TestDeleteDataBrokerRecord(t *testing.T) {
	t.Parallel()

	backend := databroker.NewBackendServer(noop.NewTracerProvider())
	cc := testutil.NewGRPCServer(t, func(s *grpc.Server) {
		databrokerpb.RegisterDataBrokerServiceServer(s, backend)
	})
	client := databrokerpb.NewDataBrokerServiceClient(cc)

	s1 := databrokerpb.NewRecord(&session.Session{Id: "s1"})
	res, err := client.Put(t.Context(), &databrokerpb.PutRequest{Records: []*databrokerpb.Record{s1}})
	require.NoError(t, err)
	s1 = res.Records[0]

	querierWithLocalCache := storage.NewCachingQuerier(storage.NewQuerier(client), storage.NewGlobalCache(time.Hour))
	querierWithLocalAndGlobalCache := storage.NewCachingQuerier(querierWithLocalCache, storage.GlobalCache)

	// get the record and fill the caches
	s2, err := storage.GetDataBrokerRecord(storage.WithQuerier(t.Context(), querierWithLocalAndGlobalCache), s1.Type, s1.Id, 0)
	require.NoError(t, err)
	assert.Empty(t, cmp.Diff(s1, s2, protocmp.Transform()))

	// delete the record, but only with the querier using the local cache
	s3, err := storage.DeleteDataBrokerRecord(storage.WithQuerier(t.Context(), querierWithLocalCache), client, s1.Type, s1.Id)
	require.NoError(t, err)
	assert.NotEmpty(t, s3.DeletedAt)
	s3.DeletedAt = nil
	assert.Empty(t, cmp.Diff(s1, s3, protocmp.Transform()))

	// ensure the local cache is invalidated
	_, err = storage.GetDataBrokerRecord(storage.WithQuerier(t.Context(), querierWithLocalCache), s1.Type, s1.Id, 0)
	assert.Equal(t, codes.NotFound, status.Code(err), "should invalidate cache")

	// ensure the global cache is invalidated even though it wasn't used with the delete call
	_, err = storage.GetDataBrokerRecord(storage.WithQuerier(t.Context(), querierWithLocalAndGlobalCache), s1.Type, s1.Id, 0)
	assert.Equal(t, codes.NotFound, status.Code(err), "should invalidate global cache")
}
