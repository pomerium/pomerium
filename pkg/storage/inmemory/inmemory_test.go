package inmemory

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/anypb"
)

func TestDB(t *testing.T) {
	ctx := context.Background()
	db := NewDB("example", 2)
	t.Run("get missing record", func(t *testing.T) {
		record, err := db.Get(ctx, "abcd")
		require.Error(t, err)
		assert.Nil(t, record)
	})
	t.Run("get record", func(t *testing.T) {
		data := new(anypb.Any)
		assert.NoError(t, db.Put(ctx, "abcd", data))
		record, err := db.Get(ctx, "abcd")
		require.NoError(t, err)
		if assert.NotNil(t, record) {
			assert.NotNil(t, record.CreatedAt)
			assert.Equal(t, data, record.Data)
			assert.Nil(t, record.DeletedAt)
			assert.Equal(t, "abcd", record.Id)
			assert.NotNil(t, record.ModifiedAt)
			assert.Equal(t, "example", record.Type)
			assert.Equal(t, "000000000001", record.Version)
		}
	})
	t.Run("delete record", func(t *testing.T) {
		assert.NoError(t, db.Delete(ctx, "abcd"))
		record, err := db.Get(ctx, "abcd")
		require.NoError(t, err)
		if assert.NotNil(t, record) {
			assert.NotNil(t, record.DeletedAt)
		}
	})
	t.Run("clear deleted", func(t *testing.T) {
		db.ClearDeleted(ctx, time.Now().Add(time.Second))
		record, err := db.Get(ctx, "abcd")
		require.Error(t, err)
		assert.Nil(t, record)
	})
	t.Run("keep remaining", func(t *testing.T) {
		data := new(anypb.Any)
		assert.NoError(t, db.Put(ctx, "abcd", data))
		assert.NoError(t, db.Delete(ctx, "abcd"))
		db.ClearDeleted(ctx, time.Now().Add(-10*time.Second))
		record, err := db.Get(ctx, "abcd")
		require.NoError(t, err)
		assert.NotNil(t, record)
		db.ClearDeleted(ctx, time.Now().Add(time.Second))
	})
	t.Run("list", func(t *testing.T) {
		for i := 0; i < 10; i++ {
			data := new(anypb.Any)
			assert.NoError(t, db.Put(ctx, fmt.Sprintf("%02d", i), data))
		}

		records, err := db.List(ctx, "")
		require.NoError(t, err)
		assert.Len(t, records, 10)
		records, err = db.List(ctx, "00000000000A")
		require.NoError(t, err)
		assert.Len(t, records, 4)
		records, err = db.List(ctx, "00000000000F")
		require.NoError(t, err)
		assert.Len(t, records, 0)
	})
}
