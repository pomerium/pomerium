package evaluator

import (
	"context"
	"testing"
	"time"

	"github.com/golang/protobuf/ptypes"
	"github.com/open-policy-agent/opa/storage"
	"github.com/stretchr/testify/assert"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/user"
)

func TestStore(t *testing.T) {
	ctx, clearTimeout := context.WithTimeout(context.Background(), time.Second*10)
	defer clearTimeout()

	s := NewStore()
	t.Run("records", func(t *testing.T) {
		u := &user.User{
			Version: "v1",
			Id:      "u1",
			Name:    "name",
			Email:   "name@example.com",
		}
		any, _ := ptypes.MarshalAny(u)
		s.UpdateRecord(&databroker.Record{
			Version: "v1",
			Type:    any.GetTypeUrl(),
			Id:      u.GetId(),
			Data:    any,
		})

		v, err := storage.ReadOne(ctx, s.opaStore, storage.MustParsePath("/databroker_data/type.googleapis.com/user.User/u1"))
		assert.NoError(t, err)
		assert.Equal(t, map[string]interface{}{
			"version": "v1",
			"id":      "u1",
			"name":    "name",
			"email":   "name@example.com",
		}, v)

		s.UpdateRecord(&databroker.Record{
			Version:   "v2",
			Type:      any.GetTypeUrl(),
			Id:        u.GetId(),
			Data:      any,
			DeletedAt: ptypes.TimestampNow(),
		})

		v, err = storage.ReadOne(ctx, s.opaStore, storage.MustParsePath("/databroker_data/type.googleapis.com/user.User/u1"))
		assert.Error(t, err)
		assert.Nil(t, v)

		s.UpdateRecord(&databroker.Record{
			Version: "v1",
			Type:    any.GetTypeUrl(),
			Id:      u.GetId(),
			Data:    any,
		})

		v, err = storage.ReadOne(ctx, s.opaStore, storage.MustParsePath("/databroker_data/type.googleapis.com/user.User/u1"))
		assert.NoError(t, err)
		assert.NotNil(t, v)

		s.ClearRecords("type.googleapis.com/user.User")
		v, err = storage.ReadOne(ctx, s.opaStore, storage.MustParsePath("/databroker_data/type.googleapis.com/user.User/u1"))
		assert.Error(t, err)
		assert.Nil(t, v)
	})
}
