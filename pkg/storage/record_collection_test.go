package storage_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/protoutil"
	"github.com/pomerium/pomerium/pkg/storage"
)

func TestRecordCollection(t *testing.T) {
	t.Parallel()

	r1 := &databroker.Record{
		Id: "r1",
		Data: newStructAny(t, map[string]any{
			"$index": map[string]any{
				"cidr": "10.0.0.0/24",
			},
		}),
	}
	r2 := &databroker.Record{
		Id: "r2",
		Data: newStructAny(t, map[string]any{
			"$index": map[string]any{
				"cidr": "192.168.0.0/24",
			},
		}),
	}
	r3 := &databroker.Record{
		Id: "r3",
		Data: newStructAny(t, map[string]any{
			"$index": map[string]any{
				"cidr": "10.0.0.0/16",
			},
		}),
	}
	r4 := &databroker.Record{
		Id: "r4",
		Data: newStructAny(t, map[string]any{
			"$index": map[string]any{
				"cidr": "10.0.0.0/24",
			},
		}),
	}

	c := storage.NewRecordCollection()
	c.Put(r4)
	c.Put(r3)
	c.Put(r2)
	c.Put(r1)

	assert.Equal(t, 4, c.Len())

	r, ok := c.Get("r1")
	assert.True(t, ok)
	assert.Empty(t, cmp.Diff(r1, r, protocmp.Transform()),
		"should return r1")
	r, ok = c.Get("r2")
	assert.True(t, ok)
	assert.Empty(t, cmp.Diff(r2, r, protocmp.Transform()),
		"should return r2")
	r, ok = c.Get("r3")
	assert.True(t, ok)
	assert.Empty(t, cmp.Diff(r3, r, protocmp.Transform()),
		"should return r3")
	r, ok = c.Get("r4")
	assert.True(t, ok)
	assert.Empty(t, cmp.Diff(r4, r, protocmp.Transform()),
		"should return r4")

	r, ok = c.Oldest()
	assert.True(t, ok)
	assert.Empty(t, cmp.Diff(r4, r, protocmp.Transform()),
		"should return the first added record")

	r, ok = c.Newest()
	assert.True(t, ok)
	assert.Empty(t, cmp.Diff(r1, r, protocmp.Transform()),
		"should return the last added record")

	rs := c.All()
	assert.Empty(t, cmp.Diff([]*databroker.Record{r4, r3, r2, r1}, rs, protocmp.Transform()),
		"should return all records")

	rs, err := c.List(nil)
	assert.NoError(t, err)
	assert.Empty(t, cmp.Diff([]*databroker.Record{r4, r3, r2, r1}, rs, protocmp.Transform()),
		"should return all records for a nil filter")

	rs, err = c.List(storage.OrFilterExpression{
		storage.EqualsFilterExpression{Fields: []string{"id"}, Value: "r3"},
		storage.EqualsFilterExpression{Fields: []string{"id"}, Value: "r1"},
	})
	assert.NoError(t, err)
	assert.Empty(t, cmp.Diff([]*databroker.Record{r3, r1}, rs, protocmp.Transform()),
		"should return two records for or")

	rs, err = c.List(storage.EqualsFilterExpression{Fields: []string{"$index"}, Value: "10.0.0.3"})
	assert.NoError(t, err)
	assert.Empty(t, cmp.Diff([]*databroker.Record{r1, r4}, rs, protocmp.Transform()))

	r1.DeletedAt = timestamppb.Now()
	c.Put(r1)

	rs, err = c.List(storage.EqualsFilterExpression{Fields: []string{"$index"}, Value: "10.0.0.3"})
	assert.NoError(t, err)
	assert.Empty(t, cmp.Diff([]*databroker.Record{r4}, rs, protocmp.Transform()))

	r4.DeletedAt = timestamppb.Now()
	c.Put(r4)

	rs, err = c.List(storage.EqualsFilterExpression{Fields: []string{"$index"}, Value: "10.0.0.3"})
	assert.NoError(t, err)
	assert.Empty(t, cmp.Diff([]*databroker.Record{r3}, rs, protocmp.Transform()))
}

func newStructAny(t *testing.T, m map[string]any) *anypb.Any {
	t.Helper()
	s, err := structpb.NewStruct(m)
	require.NoError(t, err)
	return protoutil.NewAny(s)
}
