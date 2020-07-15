package inmemory

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/anypb"
)

func TestDB(t *testing.T) {
	ctx := context.Background()
	db := NewDB("example", 2)
	t.Run("get missing record", func(t *testing.T) {
		assert.Nil(t, db.Get(ctx, "abcd"))
	})
	t.Run("get record", func(t *testing.T) {
		data := new(anypb.Any)
		assert.NoError(t, db.Put(ctx, "abcd", data))
		record := db.Get(ctx, "abcd")
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
		record := db.Get(ctx, "abcd")
		if assert.NotNil(t, record) {
			assert.NotNil(t, record.DeletedAt)
		}
	})
	t.Run("clear deleted", func(t *testing.T) {
		db.ClearDeleted(ctx, time.Now().Add(time.Second))
		assert.Nil(t, db.Get(ctx, "abcd"))
	})
	t.Run("keep remaining", func(t *testing.T) {
		data := new(anypb.Any)
		assert.NoError(t, db.Put(ctx, "abcd", data))
		assert.NoError(t, db.Delete(ctx, "abcd"))
		db.ClearDeleted(ctx, time.Now().Add(-10*time.Second))
		assert.NotNil(t, db.Get(ctx, "abcd"))
		db.ClearDeleted(ctx, time.Now().Add(time.Second))
	})
	t.Run("list", func(t *testing.T) {
		for i := 0; i < 10; i++ {
			data := new(anypb.Any)
			assert.NoError(t, db.Put(ctx, fmt.Sprintf("%02d", i), data))
		}

		assert.Len(t, db.List(ctx, ""), 10)
		assert.Len(t, db.List(ctx, "00000000000A"), 4)
		assert.Len(t, db.List(ctx, "00000000000F"), 0)
	})
}
