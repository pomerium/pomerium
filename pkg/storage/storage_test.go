package storage

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/user"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

type mockBackend struct {
	Backend
	put    func(ctx context.Context, record *databroker.Record) (uint64, error)
	get    func(ctx context.Context, recordType, id string) (*databroker.Record, error)
	getAll func(ctx context.Context) ([]*databroker.Record, *databroker.Versions, error)
}

func (m *mockBackend) Close() error {
	return nil
}

func (m *mockBackend) Put(ctx context.Context, record *databroker.Record) (uint64, error) {
	return m.put(ctx, record)
}

func (m *mockBackend) Get(ctx context.Context, recordType, id string) (*databroker.Record, error) {
	return m.get(ctx, recordType, id)
}

func (m *mockBackend) GetAll(ctx context.Context) ([]*databroker.Record, *databroker.Versions, error) {
	return m.getAll(ctx)
}

func TestMatchAny(t *testing.T) {
	u := &user.User{Id: "id", Name: "name", Email: "email"}
	data := protoutil.NewAny(u)
	assert.True(t, MatchAny(data, ""))
	assert.True(t, MatchAny(data, "id"))
	assert.True(t, MatchAny(data, "name"))
	assert.True(t, MatchAny(data, "email"))
	assert.False(t, MatchAny(data, "nope"))
}
