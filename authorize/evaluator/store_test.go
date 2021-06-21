package evaluator

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/user"
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
		any, _ := anypb.New(u)
		s.UpdateRecord(context.Background(), 0, &databroker.Record{
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

		s.UpdateRecord(context.Background(), 0, &databroker.Record{
			Version:   2,
			Type:      any.GetTypeUrl(),
			Id:        u.GetId(),
			Data:      any,
			DeletedAt: timestamppb.Now(),
		})

		v = s.GetRecordData(any.GetTypeUrl(), u.GetId())
		assert.Nil(t, v)

		s.UpdateRecord(context.Background(), 0, &databroker.Record{
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
