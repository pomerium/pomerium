package storage

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/pomerium/pomerium/pkg/protoutil"
)

func TestGetForeignKeys(t *testing.T) {
	t.Parallel()
	type M = map[string]any
	t.Run("simple field", func(t *testing.T) {
		v, err := structpb.NewStruct(M{
			"hello": "world",
		})
		require.NoError(t, err)

		extraKeys, err := GetForeignKeys(v, []string{"hello"})
		assert.NoError(t, err)
		assert.Equal(t, []string{"world"}, extraKeys)
	})

	t.Run("nested field", func(t *testing.T) {
		v, err := structpb.NewStruct(M{
			"hello": "world",
			"nested": M{
				"hello": "nested-world",
			},
		})
		require.NoError(t, err)
		extraKeys, err := GetForeignKeys(v, []string{"hello", "nested.hello"})
		assert.NoError(t, err)
		assert.Equal(t, []string{"world", "nested-world"}, extraKeys)

		extraKeys2, err := GetForeignKeys(v, []string{"nested.hello", "hello"})
		assert.NoError(t, err)
		assert.Equal(t, []string{"nested-world", "world"}, extraKeys2)
	})

	t.Run("undefined proto field", func(t *testing.T) {
		v, err := structpb.NewStruct(M{
			"hello": "world",
			"nested": M{
				"hello": "nested-world",
			},
		})
		require.NoError(t, err)
		_, err = GetForeignKeys(v, []string{"bar"})
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrNoSuchIndex)
	})

	t.Run("unsupported field type", func(t *testing.T) {
		v, err := structpb.NewStruct(M{
			"hello": 5,
			"nested": M{
				"hello": "nested-world",
			},
		})
		require.NoError(t, err)

		_, err = GetForeignKeys(v, []string{"hello"})
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrIndexUnsupportedProtoField)
	})

}

func TestGetRecordIndex(t *testing.T) {
	type M = map[string]any
	t.Run("missing", func(t *testing.T) {
		v, err := structpb.NewStruct(M{
			"notindex": "value",
		})
		require.NoError(t, err)
		assert.Nil(t, GetRecordIndex(v))
	})
	t.Run("struct", func(t *testing.T) {
		v, err := structpb.NewStruct(M{
			"$index": M{
				"cidr": "192.168.0.0/16",
			},
		})
		require.NoError(t, err)
		assert.Equal(t, &structpb.Struct{
			Fields: map[string]*structpb.Value{
				"cidr": structpb.NewStringValue("192.168.0.0/16"),
			},
		}, GetRecordIndex(v))
	})
	t.Run("value", func(t *testing.T) {
		v, err := structpb.NewValue(M{
			"$index": M{
				"cidr": "192.168.0.0/16",
			},
		})
		require.NoError(t, err)
		assert.Equal(t, &structpb.Struct{
			Fields: map[string]*structpb.Value{
				"cidr": structpb.NewStringValue("192.168.0.0/16"),
			},
		}, GetRecordIndex(v))
	})
	t.Run("any", func(t *testing.T) {
		v, err := structpb.NewValue(M{
			"$index": M{
				"cidr": "192.168.0.0/16",
			},
		})
		require.NoError(t, err)
		data := protoutil.NewAny(v)
		assert.Equal(t, &structpb.Struct{
			Fields: map[string]*structpb.Value{
				"cidr": structpb.NewStringValue("192.168.0.0/16"),
			},
		}, GetRecordIndex(data))
	})
}
