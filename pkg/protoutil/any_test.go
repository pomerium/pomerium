package protoutil

import (
	"testing"

	"github.com/pomerium/pomerium/internal/testutil"
)

func TestToAny(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name   string
		value  any
		expect string
	}{
		{"bool", true, `{
			"@type": "type.googleapis.com/google.protobuf.BoolValue",
			"value": true
		}`},
		{"float64", 1.2345, `{
			"@type": "type.googleapis.com/google.protobuf.DoubleValue",
			"value": 1.2345
		}`},
		{"float32", float32(0.4000000059604645), `{
			"@type": "type.googleapis.com/google.protobuf.FloatValue",
			"value": 0.4
		}`},
		{"int", int(1), `{
			"@type": "type.googleapis.com/google.protobuf.Int64Value",
			"value": "1"
		}`},
		{"int8", int8(1), `{
			"@type": "type.googleapis.com/google.protobuf.Int32Value",
			"value": 1
		}`},
		{"int16", int16(1), `{
			"@type": "type.googleapis.com/google.protobuf.Int32Value",
			"value": 1
		}`},
		{"int32", int32(1), `{
			"@type": "type.googleapis.com/google.protobuf.Int32Value",
			"value": 1
		}`},
		{"int64", int64(1), `{
			"@type": "type.googleapis.com/google.protobuf.Int64Value",
			"value": "1"
		}`},
		{"string", "test", `{
			"@type": "type.googleapis.com/google.protobuf.StringValue",
			"value": "test"
		}`},
		{"uint", uint(1), `{
			"@type": "type.googleapis.com/google.protobuf.UInt64Value",
			"value": "1"
		}`},
		{"uint8", uint8(1), `{
			"@type": "type.googleapis.com/google.protobuf.UInt32Value",
			"value": 1
		}`},
		{"uint16", uint16(1), `{
			"@type": "type.googleapis.com/google.protobuf.UInt32Value",
			"value": 1
		}`},
		{"uint32", uint32(1), `{
			"@type": "type.googleapis.com/google.protobuf.UInt32Value",
			"value": 1
		}`},
		{"uint64", uint64(1), `{
			"@type": "type.googleapis.com/google.protobuf.UInt64Value",
			"value": "1"
		}`},
		{"[]any", []any{1, 2, 3, 4}, `{
			"@type": "type.googleapis.com/google.protobuf.Value",
			"value": [1,2,3,4]
		}`},
		{"map[string]any", map[string]any{"k1": "v1", "k2": "v2"}, `{
			"@type": "type.googleapis.com/google.protobuf.Value",
			"value": {"k1": "v1", "k2": "v2"}
		}`},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := ToAny(tc.value)
			testutil.AssertProtoJSONEqual(t, tc.expect, actual)
		})
	}
}
