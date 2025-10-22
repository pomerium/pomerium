package protoutil

import (
	"testing"

	"google.golang.org/protobuf/types/known/apipb"

	"github.com/pomerium/pomerium/internal/testutil"
)

func TestToValue(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name   string
		value  any
		expect string
	}{
		{"bool", true, "true"},
		{"float64", 1.2345, "1.2345"},
		{"float32", float32(0.4000000059604645), "0.4000000059604645"},
		{"int", int(1), "1"},
		{"int8", int8(1), "1"},
		{"int16", int16(1), "1"},
		{"int32", int32(1), "1"},
		{"int64", int64(1), "1"},
		{"string", "test", `"test"`},
		{"uint", uint(1), "1"},
		{"uint8", uint8(1), "1"},
		{"uint16", uint16(1), "1"},
		{"uint32", uint32(1), "1"},
		{"uint64", uint64(1), "1"},
		{"[]any", []any{1, 2, 3, 4}, `[1,2,3,4]`},
		{"map[string]any", map[string]any{"k1": "v1", "k2": "v2"}, `{"k1":"v1","k2":"v2"}`},
		{"Message", &apipb.Method{Name: "example"}, `{"name": "example"}`},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := ToStruct(tc.value)
			testutil.AssertProtoJSONEqual(t, tc.expect, actual)
		})
	}
}
