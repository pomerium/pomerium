// +build redis

package redis

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/gomodule/redigo/redis"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/anypb"
)

func cleanup(c redis.Conn, db *DB, t *testing.T) {
	require.NoError(t, c.Send("MULTI"))
	require.NoError(t, c.Send("DEL", db.recordType))
	require.NoError(t, c.Send("DEL", db.versionSet))
	require.NoError(t, c.Send("DEL", db.deletedSet))
	_, err := c.Do("EXEC")
	require.NoError(t, err)
}

func TestDB(t *testing.T) {
	ctx := context.Background()
	address := ":6379"
	if redisURL := os.Getenv("REDIS_URL"); redisURL != "" {
		address = redisURL
	}
	db, err := New(address, "record_type", int64(time.Hour.Seconds()))
	require.NoError(t, err)
	ids := []string{"a", "b", "c"}
	id := ids[0]
	c := db.pool.Get()
	defer c.Close()

	cleanup(c, db, t)

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
		require.NotNil(t, record)
		assert.NotNil(t, record.DeletedAt)
	})
	t.Run("clear deleted", func(t *testing.T) {
		db.ClearDeleted(ctx, time.Now().Add(time.Second))
		assert.Nil(t, db.Get(ctx, id))
	})
	t.Run("get all", func(t *testing.T) {
		assert.Len(t, db.GetAll(ctx), 0)
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
		cleanup(c, db, t)
		ids := make([]string, 0, 10)
		for i := 0; i < 10; i++ {
			id := fmt.Sprintf("%02d", i)
			ids = append(ids, id)
			data := new(anypb.Any)
			assert.NoError(t, db.Put(ctx, id, data))
		}

		assert.Len(t, db.List(ctx, ""), 10)
		assert.Len(t, db.List(ctx, "00000000000A"), 5)
		assert.Len(t, db.List(ctx, "00000000000F"), 0)

		for _, id := range ids {
			_, _ = c.Do("DEL", id)
		}
	})
}
