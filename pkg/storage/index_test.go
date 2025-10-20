package storage

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/pomerium/pomerium/pkg/protoutil"
)

func TestGetRecordIndex(t *testing.T) {
	t.Parallel()

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
