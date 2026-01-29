package synccache_test

import (
	"bytes"
	"context"
	"iter"
	"testing"
	"time"

	"github.com/cockroachdb/pebble/v2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"
	grpc "google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/internal/databroker"
	"github.com/pomerium/pomerium/internal/testutil"
	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/user"
	"github.com/pomerium/pomerium/pkg/pebbleutil"
	"github.com/pomerium/pomerium/pkg/protoutil"
	"github.com/pomerium/pomerium/pkg/synccache"
)

func TestSyncCache(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(t.Context(), time.Second*15)
	defer cancel()

	prefix := []byte{1, 2, 3}
	typeUUID := uuid.MustParse("e86635f2-f7ad-594d-a37e-a447aca46801")

	srv1 := databroker.NewBackendServer(noop.NewTracerProvider())
	t.Cleanup(srv1.Stop)
	cc1 := testutil.NewGRPCServer(t, func(s *grpc.Server) {
		databrokerpb.RegisterDataBrokerServiceServer(s, srv1)
	})
	srv2 := databroker.NewBackendServer(noop.NewTracerProvider())
	t.Cleanup(srv2.Stop)
	cc2 := testutil.NewGRPCServer(t, func(s *grpc.Server) {
		databrokerpb.RegisterDataBrokerServiceServer(s, srv2)
	})
	client1 := databrokerpb.NewDataBrokerServiceClient(cc1)
	client2 := databrokerpb.NewDataBrokerServiceClient(cc2)

	expected := []*databrokerpb.Record{
		databrokerpb.NewRecord(&user.User{Id: "u1"}),
		databrokerpb.NewRecord(&user.User{Id: "u2"}),
		databrokerpb.NewRecord(&user.User{Id: "u3"}),
	}
	res, err := client1.Put(ctx, &databrokerpb.PutRequest{Records: expected})
	require.NoError(t, err)
	expected = res.Records

	db := pebbleutil.MustOpenMemory(nil)
	require.NoError(t, db.Set([]byte("OTHER"), []byte("VALUE"), nil))
	c := synccache.New(db, prefix)

	assert.NoError(t, c.Sync(ctx, client1, protoutil.GetTypeURL(new(user.User))))
	actual := collect(t, c.Records(protoutil.GetTypeURL(new(user.User))))
	testutil.AssertProtoEqual(t, expected, actual)

	assert.Equal(t, [][]byte{
		append(append(prefix, typeUUID[:]...), 1),                  // server version
		append(append(prefix, typeUUID[:]...), 2),                  // record version
		append(append(append(prefix, typeUUID[:]...), 3), "u1"...), // record u1
		append(append(append(prefix, typeUUID[:]...), 3), "u2"...), // record u2
		append(append(append(prefix, typeUUID[:]...), 3), "u3"...), // record u3
		[]byte("OTHER"),
	}, collect(t, pebbleutil.IterateKeys(db, nil)))

	// test adding a new record

	u4 := databrokerpb.NewRecord(&user.User{Id: "u4"})
	res, err = client1.Put(ctx, &databrokerpb.PutRequest{Records: []*databrokerpb.Record{u4}})
	require.NoError(t, err)
	expected = append(expected, res.Records...)

	assert.NoError(t, c.Sync(ctx, client1, protoutil.GetTypeURL(new(user.User))))
	actual = collect(t, c.Records(protoutil.GetTypeURL(new(user.User))))
	testutil.AssertProtoEqual(t, expected, actual)

	// test deleting a record

	u4.DeletedAt = timestamppb.Now()
	_, err = client1.Put(ctx, &databrokerpb.PutRequest{Records: []*databrokerpb.Record{u4}})
	require.NoError(t, err)
	expected = expected[:len(expected)-1]

	assert.NoError(t, c.Sync(ctx, client1, protoutil.GetTypeURL(new(user.User))))
	actual = collect(t, c.Records(protoutil.GetTypeURL(new(user.User))))
	testutil.AssertProtoEqual(t, expected, actual)

	// test server version change

	assert.NoError(t, c.Sync(ctx, client2, protoutil.GetTypeURL(new(user.User))))
	actual = collect(t, c.Records(protoutil.GetTypeURL(new(user.User))))
	assert.Empty(t, actual)

	// make sure clear works but other keys are left untouched

	assert.NoError(t, c.Clear(protoutil.GetTypeURL(new(user.User))))
	assert.Equal(t, [][]byte{[]byte("OTHER")}, collect(t, pebbleutil.IterateKeys(db, nil)))
}

func collect[T any](tb testing.TB, seq iter.Seq2[T, error]) []T {
	var records []T
	for record, err := range seq {
		require.NoError(tb, err)
		records = append(records, record)
	}
	return records
}

type giantRecordServer struct {
	databrokerpb.UnimplementedDataBrokerServiceServer
}

func (srv *giantRecordServer) SyncLatest(
	_ *databrokerpb.SyncLatestRequest,
	stream grpc.ServerStreamingServer[databrokerpb.SyncLatestResponse],
) error {
	for range 1024 * 5 {
		err := stream.Send(&databrokerpb.SyncLatestResponse{
			Response: &databrokerpb.SyncLatestResponse_Record{
				Record: &databrokerpb.Record{
					Data: protoutil.NewAnyBytes(bytes.Repeat([]byte{0x01}, 1024*1024)),
				},
			},
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func TestLargeBatch(t *testing.T) {
	t.Skip("this test uses a very large amount of memory so needs to be run manually")

	srv := &giantRecordServer{}
	cc := testutil.NewGRPCServer(t, func(s *grpc.Server) {
		databrokerpb.RegisterDataBrokerServiceServer(s, srv)
	})

	db := pebbleutil.MustOpenMemory(&pebble.Options{})
	cache := synccache.New(db, []byte{0x00})
	err := cache.Sync(t.Context(), databrokerpb.NewDataBrokerServiceClient(cc), "TEST")
	assert.NoError(t, err)
}
