package databroker_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/pomerium/datasource/pkg/directory"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/protoutil"
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
		Type: directory.UserRecordType,
		Id:   "user-1",
		Data: protoutil.NewAny(mustNewStruct(map[string]any{
			"email": "user-1@example.com",
		})),
	})
	rsb2 = databroker.RecordSetBundle{}
	updates = databroker.GetChangeSet(rsb1, rsb2, func(record1, record2 *databroker.Record) bool {
		return cmp.Equal(record1, record2, protocmp.Transform())
	})
	if assert.Len(t, updates, 1) {
		assert.Equal(t, directory.UserRecordType, updates[0].GetType())
		assert.Equal(t, "type.googleapis.com/google.protobuf.Struct", updates[0].GetData().GetTypeUrl(),
			"should preserve data type")
		assert.NotNil(t, updates[0].GetDeletedAt())
	}
}

func mustNewStruct(m map[string]any) *structpb.Struct {
	s, err := structpb.NewStruct(m)
	if err != nil {
		panic(err)
	}
	return s
}
