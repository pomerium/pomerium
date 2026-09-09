package mapsutil_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/pomerium/pomerium/pkg/mapsutil"
)

func TestFlatten(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name     string
		in       map[string]any
		expected map[string][]any
	}{
		{"empty", map[string]any{}, map[string][]any{}},
		{"nil", nil, map[string][]any{}},
		{
			"scalar",
			map[string]any{"a": 1, "b": "x", "c": true, "d": nil},
			map[string][]any{"a": {1}, "b": {"x"}, "c": {true}, "d": {nil}},
		},
		{
			"slice",
			map[string]any{"a": []any{1, 2}},
			map[string][]any{"a": {1, 2}},
		},
		{
			"empty_slice",
			map[string]any{"a": []any{}},
			map[string][]any{"a": {}},
		},
		{
			"nested",
			map[string]any{"a": map[string]any{"b": map[string]any{"c": 12345}}},
			map[string][]any{"a.b.c": {12345}},
		},
		{
			"nested_siblings",
			map[string]any{"a": map[string]any{"b": 1, "c": []any{2, 3}}, "d": 4},
			map[string][]any{"a.b": {1}, "a.c": {2, 3}, "d": {4}},
		},
		{
			"empty_nested",
			map[string]any{"a": map[string]any{}, "b": 1},
			map[string][]any{"b": {1}},
		},
		{
			"typed_map",
			map[string]any{"a": map[string]string{"b": "c"}},
			map[string][]any{"a.b": {"c"}},
		},
		{
			"typed_slice",
			map[string]any{"a": []string{"b", "c"}},
			map[string][]any{"a": {"b", "c"}},
		},
		{
			"non_string_keys",
			map[string]any{"a": map[int]any{1: "b"}},
			map[string][]any{"a.1": {"b"}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.expected, mapsutil.Flatten(tc.in))
		})
	}
}
