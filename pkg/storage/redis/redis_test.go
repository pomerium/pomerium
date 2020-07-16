// +build redis

package redis

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/gomodule/redigo/redis"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/anypb"
)

func TestDB(t *testing.T) {
	ctx := context.Background()
	address := ":6379"
	if redisURL := os.Getenv("REDIS_URL"); redisURL != "" {
		address = redisURL
	}
	db, err := New(address)
	require.NoError(t, err)
	ids := []string{"a", "b", "c"}
	id := ids[0]
	c := db.pool.Get()
	defer c.Close()
	_, _ = c.Do("DEL", id)

	t.Run("get missing record", func(t *testing.T) {
		assert.Nil(t, db.Get(ctx, id))
	})
	t.Run("get record", func(t *testing.T) {
		data := new(anypb.Any)
		assert.NoError(t, db.Put(ctx, id, data))
		record := db.Get(ctx, id)
		if assert.NotNil(t, record) {
			assert.NotNil(t, record.CreatedAt)
			assert.Equal(t, data, record.Data)
			assert.Nil(t, record.DeletedAt)
			assert.Equal(t, "a", record.Id)
			assert.NotNil(t, record.ModifiedAt)
			assert.Equal(t, "000000000001", record.Version)
		}
	})
	t.Run("delete record", func(t *testing.T) {
		assert.NoError(t, db.Delete(ctx, id))
		record := db.Get(ctx, id)
		if assert.NotNil(t, record) {
			assert.NotNil(t, record.DeletedAt)
		}
		ttl, err := redis.Int64(c.Do("TTL", id))
		assert.NoError(t, err)
		assert.Greater(t, ttl, int64(0))
	})
	t.Run("get all", func(t *testing.T) {
		assert.Len(t, db.GetAll(ctx), 1)
		data := new(anypb.Any)

		for _, id := range ids {
			assert.NoError(t, db.Put(ctx, id, data))
		}
		assert.Len(t, db.GetAll(ctx), len(ids))
		for _, id := range ids {
			_, _ = c.Do("DEL", id)
		}
	})
	t.Run("list", func(t *testing.T) {
		ids := make([]string, 0, 10)
		for i := 0; i < 10; i++ {
			id := fmt.Sprintf("%02d", i)
			ids = append(ids, id)
			data := new(anypb.Any)
			assert.NoError(t, db.Put(ctx, id, data))
		}

		assert.Len(t, db.List(ctx, ""), 10)
		assert.Len(t, db.List(ctx, "00000000000A"), 4)
		assert.Len(t, db.List(ctx, "00000000000F"), 0)

		for _, id := range ids {
			_, _ = c.Do("DEL", id)
		}
	})
}
