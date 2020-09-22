package storage

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/user"
)

type mockBackend struct {
	put          func(ctx context.Context, id string, data *anypb.Any) error
	get          func(ctx context.Context, id string) (*databroker.Record, error)
	getAll       func(ctx context.Context) ([]*databroker.Record, error)
	list         func(ctx context.Context, sinceVersion string) ([]*databroker.Record, error)
	delete       func(ctx context.Context, id string) error
	clearDeleted func(ctx context.Context, cutoff time.Time)
	query        func(ctx context.Context, query string, offset, limit int) ([]*databroker.Record, int, error)
	watch        func(ctx context.Context) <-chan struct{}
}

func (m *mockBackend) Close() error {
	return nil
}

func (m *mockBackend) Put(ctx context.Context, id string, data *anypb.Any) error {
	return m.put(ctx, id, data)
}

func (m *mockBackend) Get(ctx context.Context, id string) (*databroker.Record, error) {
	return m.get(ctx, id)
}

func (m *mockBackend) GetAll(ctx context.Context) ([]*databroker.Record, error) {
	return m.getAll(ctx)
}

func (m *mockBackend) List(ctx context.Context, sinceVersion string) ([]*databroker.Record, error) {
	return m.list(ctx, sinceVersion)
}

func (m *mockBackend) Delete(ctx context.Context, id string) error {
	return m.delete(ctx, id)
}

func (m *mockBackend) ClearDeleted(ctx context.Context, cutoff time.Time) {
	m.clearDeleted(ctx, cutoff)
}

func (m *mockBackend) Query(ctx context.Context, query string, offset, limit int) ([]*databroker.Record, int, error) {
	return m.query(ctx, query, offset, limit)
}

func (m *mockBackend) Watch(ctx context.Context) <-chan struct{} {
	return m.watch(ctx)
}

func TestMatchAny(t *testing.T) {
	u := &user.User{Id: "id", Name: "name", Email: "email"}
	data, _ := anypb.New(u)
	assert.True(t, MatchAny(data, ""))
	assert.True(t, MatchAny(data, "id"))
	assert.True(t, MatchAny(data, "name"))
	assert.True(t, MatchAny(data, "email"))
	assert.False(t, MatchAny(data, "nope"))
}
