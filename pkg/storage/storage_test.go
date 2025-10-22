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
	put func(ctx context.Context, records []*databroker.Record) (uint64, error)
	get func(ctx context.Context, recordType, id string) (*databroker.Record, error)
}

func (m *mockBackend) Close() error {
	return nil
}

func (m *mockBackend) Put(ctx context.Context, records []*databroker.Record) (uint64, error) {
	return m.put(ctx, records)
}

func (m *mockBackend) Get(ctx context.Context, recordType, id string) (*databroker.Record, error) {
	return m.get(ctx, recordType, id)
}

func TestMatchAny(t *testing.T) {
	t.Parallel()

	u := &user.User{Id: "id", Name: "name", Email: "email"}
	data := protoutil.NewAny(u)
	assert.True(t, MatchAny(data, ""))
	assert.True(t, MatchAny(data, "id"))
	assert.True(t, MatchAny(data, "name"))
	assert.True(t, MatchAny(data, "email"))
	assert.False(t, MatchAny(data, "nope"))
}
