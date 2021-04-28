package storage

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/pomerium/pomerium/pkg/cryptutil"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
)

func TestEncryptedBackend(t *testing.T) {
	ctx := context.Background()

	m := map[string]*anypb.Any{}
	backend := &mockBackend{
		put: func(ctx context.Context, record *databroker.Record) (uint64, error) {
			record.ModifiedAt = timestamppb.Now()
			record.Version++
			m[record.GetId()] = record.GetData()
			return 0, nil
		},
		get: func(ctx context.Context, recordType, id string) (*databroker.Record, error) {
			data, ok := m[id]
			if !ok {
				return nil, errors.New("not found")
			}
			return &databroker.Record{
				Id:         id,
				Data:       data,
				Version:    1,
				ModifiedAt: timestamppb.Now(),
			}, nil
		},
		getAll: func(ctx context.Context) ([]*databroker.Record, *databroker.Versions, error) {
			var records []*databroker.Record
			for id, data := range m {
				records = append(records, &databroker.Record{
					Id:         id,
					Data:       data,
					Version:    1,
					ModifiedAt: timestamppb.Now(),
				})
			}
			return records, &databroker.Versions{}, nil
		},
	}

	e, err := NewEncryptedBackend(cryptutil.NewKey(), backend)
	if !assert.NoError(t, err) {
		return
	}

	any, _ := anypb.New(wrapperspb.String("HELLO WORLD"))

	rec := &databroker.Record{
		Type: "",
		Id:   "TEST-1",
		Data: any,
	}
	_, err = e.Put(ctx, rec)
	if !assert.NoError(t, err) {
		return
	}
	if assert.NotNil(t, m["TEST-1"], "key should be set") {
		assert.NotEqual(t, any.TypeUrl, m["TEST-1"].TypeUrl, "encrypted data should be a bytes type")
		assert.NotEqual(t, any.Value, m["TEST-1"].Value, "value should be encrypted")
		assert.NotNil(t, rec.ModifiedAt)
		assert.NotZero(t, rec.Version)
	}

	record, err := e.Get(ctx, "", "TEST-1")
	if !assert.NoError(t, err) {
		return
	}
	assert.Equal(t, any.TypeUrl, record.Data.TypeUrl, "type should be preserved")
	assert.Equal(t, any.Value, record.Data.Value, "value should be preserved")
	assert.Equal(t, any.TypeUrl, record.Type, "record type should be preserved")

	records, _, err := e.GetAll(ctx)
	if !assert.NoError(t, err) {
		return
	}
	if assert.Len(t, records, 1) {
		assert.Equal(t, any.TypeUrl, records[0].Data.TypeUrl, "type should be preserved")
		assert.Equal(t, any.Value, records[0].Data.Value, "value should be preserved")
		assert.Equal(t, any.TypeUrl, records[0].Type, "record type should be preserved")
	}
}
