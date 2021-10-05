package evaluator

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/user"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

func TestStore(t *testing.T) {
	s := NewStore()
	t.Run("records", func(t *testing.T) {
		u := &user.User{
			Version: "v1",
			Id:      "u1",
			Name:    "name",
			Email:   "name@example.com",
		}
		any := protoutil.NewAny(u)
		s.UpdateRecord(0, &databroker.Record{
			Version: 1,
			Type:    any.GetTypeUrl(),
			Id:      u.GetId(),
			Data:    any,
		})

		v := s.GetRecordData(any.GetTypeUrl(), u.GetId())
		assert.Equal(t, map[string]interface{}{
			"version": "v1",
			"id":      "u1",
			"name":    "name",
			"email":   "name@example.com",
		}, toMap(v))

		s.UpdateRecord(0, &databroker.Record{
			Version:   2,
			Type:      any.GetTypeUrl(),
			Id:        u.GetId(),
			Data:      any,
			DeletedAt: timestamppb.Now(),
		})

		v = s.GetRecordData(any.GetTypeUrl(), u.GetId())
		assert.Nil(t, v)

		s.UpdateRecord(0, &databroker.Record{
			Version: 3,
			Type:    any.GetTypeUrl(),
			Id:      u.GetId(),
			Data:    any,
		})

		v = s.GetRecordData(any.GetTypeUrl(), u.GetId())
		assert.NotNil(t, v)

		s.ClearRecords()
		v = s.GetRecordData(any.GetTypeUrl(), u.GetId())
		assert.Nil(t, v)
	})
}
