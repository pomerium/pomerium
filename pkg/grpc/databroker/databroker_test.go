package databroker

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestCompositeRecordID(t *testing.T) {
	t.Parallel()

	t.Run("deterministic regardless of map iteration", func(t *testing.T) {
		// Keys are sorted alphabetically, so output is always the same.
		id1 := CompositeRecordID(map[string]any{"host": "example.com", "user_id": "user1"})
		id2 := CompositeRecordID(map[string]any{"user_id": "user1", "host": "example.com"})
		assert.Equal(t, id1, id2)
		assert.Equal(t, "host=example.com&user_id=user1", id1)
	})

	t.Run("non-string values", func(t *testing.T) {
		id := CompositeRecordID(map[string]any{"count": 42, "enabled": true})
		assert.Equal(t, "count=42&enabled=true", id)
	})

	t.Run("url-encodes special characters", func(t *testing.T) {
		id := CompositeRecordID(map[string]any{"host": "example.com:443", "path": "/a&b=c"})
		assert.Equal(t, "host=example.com%3A443&path=%2Fa%26b%3Dc", id)
	})

	t.Run("single key", func(t *testing.T) {
		id := CompositeRecordID(map[string]any{"id": "simple"})
		assert.Equal(t, "id=simple", id)
	})
}

func TestApplyOffsetAndLimit(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name          string
		records       []*Record
		offset, limit int
		expect        []*Record
	}{
		{
			name:    "empty",
			records: nil,
			offset:  10,
			limit:   5,
			expect:  nil,
		},
		{
			name:    "less than limit",
			records: []*Record{{Id: "A"}, {Id: "B"}, {Id: "C"}, {Id: "D"}},
			offset:  1,
			limit:   10,
			expect:  []*Record{{Id: "B"}, {Id: "C"}, {Id: "D"}},
		},
		{
			name:    "more than limit",
			records: []*Record{{Id: "A"}, {Id: "B"}, {Id: "C"}, {Id: "D"}, {Id: "E"}, {Id: "F"}, {Id: "G"}, {Id: "H"}},
			offset:  3,
			limit:   2,
			expect:  []*Record{{Id: "D"}, {Id: "E"}},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			actual, cnt := ApplyOffsetAndLimit(tc.records, tc.offset, tc.limit)
			assert.Equal(t, len(tc.records), cnt)
			assert.Equal(t, tc.expect, actual)
		})
	}
}

func TestOptimumPutRequestsFromRecords(t *testing.T) {
	t.Parallel()

	var records []*Record
	for i := range 10_000 {
		s := structpb.NewStructValue(&structpb.Struct{
			Fields: map[string]*structpb.Value{
				"long_string": structpb.NewStringValue(strings.Repeat("x", 987)),
			},
		})
		records = append(records, &Record{
			Id:   fmt.Sprintf("%d", i),
			Data: newAny(s),
		})
	}
	requests := OptimumPutRequestsFromRecords(records)
	for _, request := range requests {
		assert.LessOrEqual(t, proto.Size(request), maxMessageSize)
		assert.GreaterOrEqual(t, proto.Size(request), maxMessageSize/2)
	}
}
