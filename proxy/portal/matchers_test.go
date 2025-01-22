package portal

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/pkg/policy/parser"
)

func Test_matchString(t *testing.T) {
	t.Parallel()

	t.Run("string", func(t *testing.T) {
		assert.True(t, matchString("TEST", mustParseValue(t, `"TEST"`)))
	})
	t.Run("bool", func(t *testing.T) {
		assert.False(t, matchString("true", mustParseValue(t, `true`)))
	})
	t.Run("number", func(t *testing.T) {
		assert.False(t, matchString("1", mustParseValue(t, `1`)))
	})
	t.Run("null", func(t *testing.T) {
		assert.False(t, matchString("null", mustParseValue(t, `null`)))
	})
	t.Run("array", func(t *testing.T) {
		assert.False(t, matchString("[]", mustParseValue(t, `[]`)))
	})
	t.Run("contains", func(t *testing.T) {
		assert.True(t, matchString("XYZ", mustParseValue(t, `{"contains":"Y"}`)))
		assert.False(t, matchString("XYZ", mustParseValue(t, `{"contains":"A"}`)))
	})
	t.Run("ends_with", func(t *testing.T) {
		assert.True(t, matchString("XYZ", mustParseValue(t, `{"ends_with":"Z"}`)))
		assert.False(t, matchString("XYZ", mustParseValue(t, `{"ends_with":"X"}`)))
	})
	t.Run("is", func(t *testing.T) {
		assert.True(t, matchString("XYZ", mustParseValue(t, `{"is":"XYZ"}`)))
		assert.False(t, matchString("XYZ", mustParseValue(t, `{"is":"X"}`)))
	})
	t.Run("starts_with", func(t *testing.T) {
		assert.True(t, matchString("XYZ", mustParseValue(t, `{"starts_with":"X"}`)))
		assert.False(t, matchString("XYZ", mustParseValue(t, `{"starts_with":"Z"}`)))
	})
}

func Test_matchStringList(t *testing.T) {
	t.Parallel()

	t.Run("string", func(t *testing.T) {
		assert.True(t, matchStringList([]string{"X", "Y", "Z"}, mustParseValue(t, `"Y"`)))
		assert.False(t, matchStringList([]string{"X", "Y", "Z"}, mustParseValue(t, `"A"`)))
	})
	t.Run("bool", func(t *testing.T) {
		assert.False(t, matchStringList([]string{"true"}, mustParseValue(t, `true`)))
	})
	t.Run("number", func(t *testing.T) {
		assert.False(t, matchStringList([]string{"1"}, mustParseValue(t, `1`)))
	})
	t.Run("null", func(t *testing.T) {
		assert.False(t, matchStringList([]string{"null"}, mustParseValue(t, `null`)))
	})
	t.Run("array", func(t *testing.T) {
		assert.False(t, matchStringList([]string{"[]"}, mustParseValue(t, `[]`)))
	})
	t.Run("has", func(t *testing.T) {
		assert.True(t, matchStringList([]string{"X", "Y", "Z"}, mustParseValue(t, `{"has":"Y"}`)))
		assert.False(t, matchStringList([]string{"X", "Y", "Z"}, mustParseValue(t, `{"has":"A"}`)))
	})
	t.Run("is", func(t *testing.T) {
		assert.True(t, matchStringList([]string{"X"}, mustParseValue(t, `{"is":"X"}`)))
		assert.False(t, matchStringList([]string{"X", "Y", "Z"}, mustParseValue(t, `{"is":"Y"}`)))
		assert.False(t, matchStringList([]string{"X", "Y", "Z"}, mustParseValue(t, `{"is":"A"}`)))
	})
}

func mustParseValue(t testing.TB, raw string) parser.Value {
	v, err := parser.ParseValue(strings.NewReader(raw))
	require.NoError(t, err)
	return v
}
