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
	ctx, cancelFunc := context.WithCancel(context.Background())
	defer cancelFunc()
	address := "redis://localhost/6379/0"
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
	_, err = c.Do("DEL", db.lastVersionKey)
	require.NoError(t, err)

	ch := db.Watch(ctx)

	t.Run("get missing record", func(t *testing.T) {
		record, err := db.Get(ctx, id)
		assert.Error(t, err)
		assert.Nil(t, record)
	})
	t.Run("get record", func(t *testing.T) {
		data := new(anypb.Any)
		assert.NoError(t, db.Put(ctx, id, data))
		record, err := db.Get(ctx, id)
		require.NoError(t, err)
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
		record, err := db.Get(ctx, id)
		require.NoError(t, err)
		require.NotNil(t, record)
		assert.NotNil(t, record.DeletedAt)
	})
	t.Run("clear deleted", func(t *testing.T) {
		db.ClearDeleted(ctx, time.Now().Add(time.Second))
		record, err := db.Get(ctx, id)
		assert.Error(t, err)
		assert.Nil(t, record)
	})
	t.Run("get all", func(t *testing.T) {
		records, err := db.GetAll(ctx)
		assert.NoError(t, err)
		assert.Len(t, records, 0)
		data := new(anypb.Any)

		for _, id := range ids {
			assert.NoError(t, db.Put(ctx, id, data))
		}
		records, err = db.GetAll(ctx)
		assert.NoError(t, err)
		assert.Len(t, records, len(ids))
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

		records, err := db.List(ctx, "")
		assert.NoError(t, err)
		assert.Len(t, records, 10)
		records, err = db.List(ctx, "00000000000A")
		assert.NoError(t, err)
		assert.Len(t, records, 5)
		records, err = db.List(ctx, "00000000000F")
		assert.NoError(t, err)
		assert.Len(t, records, 0)
	})

	expectedNumEvents := 14
	actualNumEvents := 0
	for range ch {
		actualNumEvents++
		if actualNumEvents == expectedNumEvents {
			cancelFunc()
		}
	}
}
