package store

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestByID(t *testing.T) {
	idx := newIndex()

	r1 := &structpb.Struct{Fields: map[string]*structpb.Value{
		"id": structpb.NewStringValue("r1"),
	}}

	idx.set("example.com/record", "r1", r1)
	assert.Equal(t, r1, idx.get("example.com/record", "r1"))
	idx.delete("example.com/record", "r1")
	assert.Nil(t, idx.get("example.com/record", "r1"))
}

func TestByCIDR(t *testing.T) {
	t.Run("ipv4", func(t *testing.T) {
		idx := newIndex()

		r1 := &structpb.Struct{Fields: map[string]*structpb.Value{
			"$index": structpb.NewStructValue(&structpb.Struct{Fields: map[string]*structpb.Value{
				"cidr": structpb.NewStringValue("192.168.0.0/16"),
			}}),
			"id": structpb.NewStringValue("r1"),
		}}
		idx.set("example.com/record", "r1", r1)

		r2 := &structpb.Struct{Fields: map[string]*structpb.Value{
			"$index": structpb.NewStructValue(&structpb.Struct{Fields: map[string]*structpb.Value{
				"cidr": structpb.NewStringValue("192.168.0.0/24"),
			}}),
			"id": structpb.NewStringValue("r2"),
		}}
		idx.set("example.com/record", "r2", r2)

		assert.Equal(t, r2, idx.find("example.com/record", "192.168.0.7"))
		idx.delete("example.com/record", "r2")
		assert.Equal(t, r1, idx.find("example.com/record", "192.168.0.7"))
		idx.delete("example.com/record", "r1")
		assert.Nil(t, idx.find("example.com/record", "192.168.0.7"))
	})
	t.Run("ipv6", func(t *testing.T) {
		idx := newIndex()

		r1 := &structpb.Struct{Fields: map[string]*structpb.Value{
			"$index": structpb.NewStructValue(&structpb.Struct{Fields: map[string]*structpb.Value{
				"cidr": structpb.NewStringValue("2001:db8::/32"),
			}}),
			"id": structpb.NewStringValue("r1"),
		}}
		idx.set("example.com/record", "r1", r1)

		r2 := &structpb.Struct{Fields: map[string]*structpb.Value{
			"$index": structpb.NewStructValue(&structpb.Struct{Fields: map[string]*structpb.Value{
				"cidr": structpb.NewStringValue("2001:db8::/48"),
			}}),
			"id": structpb.NewStringValue("r2"),
		}}
		idx.set("example.com/record", "r2", r2)

		assert.Equal(t, r2, idx.find("example.com/record", "2001:db8::"))
		idx.delete("example.com/record", "r2")
		assert.Equal(t, r1, idx.find("example.com/record", "2001:db8::"))
		idx.delete("example.com/record", "r1")
		assert.Nil(t, idx.find("example.com/record", "2001:db8::"))
	})
}
