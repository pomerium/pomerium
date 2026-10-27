package databroker_test

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
)

func TestGetChangeset(t *testing.T) {
	t.Parallel()

	rsb1 := databroker.RecordSetBundle{}
	rsb2 := databroker.RecordSetBundle{}
	updates := databroker.GetChangeSet(rsb1, rsb2, func(record1, record2 *databroker.Record) bool {
		return cmp.Equal(record1, record2, protocmp.Transform())
	})
	assert.Len(t, updates, 0)

	rsb1 = databroker.RecordSetBundle{}
	rsb1.Add(&databroker.Record{
		Type: "pomerium.io/DirectoryUser",
		Id:   "user-1",
		Data: mustNewAny(mustNewStruct(map[string]any{
			"email": "user-1@example.com",
		})),
	})
	rsb2 = databroker.RecordSetBundle{}
	updates = databroker.GetChangeSet(rsb1, rsb2, func(record1, record2 *databroker.Record) bool {
		return cmp.Equal(record1, record2, protocmp.Transform())
	})
	if assert.Len(t, updates, 1) {
		assert.Equal(t, "pomerium.io/DirectoryUser", updates[0].GetType())
		assert.Equal(t, "type.googleapis.com/google.protobuf.Struct", updates[0].GetData().GetTypeUrl(),
			"should preserve data type")
		assert.NotNil(t, updates[0].GetDeletedAt())
	}
}

type mockPutMultiClient struct {
	databroker.DataBrokerServiceClient
	put func(ctx context.Context, req *databroker.PutRequest) (*databroker.PutResponse, error)
}

func (c mockPutMultiClient) Put(ctx context.Context, req *databroker.PutRequest, opts ...grpc.CallOption) (*databroker.PutResponse, error) {
	return c.put(ctx, req)
}

func TestPutMulti(t *testing.T) {
	t.Parallel()

	r1 := &databroker.Record{
		Type: "pomerium.io/DirectoryUser",
		Id:   "user-1",
		Data: mustNewAny(mustNewStruct(map[string]any{
			"email": "user-1@example.com",
		})),
	}
	err := databroker.PutMulti(t.Context(), mockPutMultiClient{
		put: func(ctx context.Context, req *databroker.PutRequest) (*databroker.PutResponse, error) {
			res := new(databroker.PutResponse)
			v := uint64(1)
			for _, record := range req.Records {
				record = proto.CloneOf(record)
				record.Version = v
				res.Records = append(res.Records, record)
				v++
			}
			return res, nil
		},
	}, r1)
	require.NoError(t, err)
	assert.NotZero(t, r1.GetVersion(), "should update the record in place")
}

func mustNewAny(m proto.Message) *anypb.Any {
	a, err := anypb.New(m)
	if err != nil {
		panic(err)
	}
	return a
}

func mustNewStruct(m map[string]any) *structpb.Struct {
	s, err := structpb.NewStruct(m)
	if err != nil {
		panic(err)
	}
	return s
}
