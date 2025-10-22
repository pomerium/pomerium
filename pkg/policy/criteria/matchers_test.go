package criteria

import (
	"strings"
	"testing"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/format"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/pkg/policy/parser"
)

func TestStringMatcher(t *testing.T) {
	t.Parallel()

	str := func(x any) string {
		bs := format.MustAst(x)
		return strings.TrimSpace(string(bs))
	}

	t.Run("contains", func(t *testing.T) {
		t.Parallel()

		var body ast.Body
		err := matchString(&body, ast.VarTerm("example"), parser.Object{
			"contains": parser.String("test"),
		})
		require.NoError(t, err)
		assert.Equal(t, `contains(example, "test")`, str(body))
	})
	t.Run("ends_with", func(t *testing.T) {
		t.Parallel()

		var body ast.Body
		err := matchString(&body, ast.VarTerm("example"), parser.Object{
			"ends_with": parser.String("test"),
		})
		require.NoError(t, err)
		assert.Equal(t, `endswith(example, "test")`, str(body))
	})
	t.Run("is", func(t *testing.T) {
		t.Parallel()

		var body ast.Body
		err := matchString(&body, ast.VarTerm("example"), parser.Object{
			"is": parser.String("test"),
		})
		require.NoError(t, err)
		assert.Equal(t, `example == "test"`, str(body))
	})
	t.Run("not", func(t *testing.T) {
		t.Parallel()

		var body ast.Body
		err := matchString(&body, ast.VarTerm("example"), parser.Object{
			"not": parser.String("test"),
		})
		require.NoError(t, err)
		assert.Equal(t, `example != "test"`, str(body))
	})
	t.Run("starts_with", func(t *testing.T) {
		t.Parallel()

		var body ast.Body
		err := matchString(&body, ast.VarTerm("example"), parser.Object{
			"starts_with": parser.String("test"),
		})
		require.NoError(t, err)
		assert.Equal(t, `startswith(example, "test")`, str(body))
	})
	t.Run("string", func(t *testing.T) {
		t.Parallel()

		var body ast.Body
		err := matchString(&body, ast.VarTerm("example"), parser.String("test"))
		require.NoError(t, err)
		assert.Equal(t, `example == "test"`, str(body))
	})
	t.Run("boolean", func(t *testing.T) {
		t.Parallel()

		var body ast.Body
		err := matchString(&body, ast.VarTerm("example"), parser.Boolean(true))
		require.NoError(t, err)
		assert.Equal(t, `example == true`, str(body))
	})
	t.Run("number", func(t *testing.T) {
		t.Parallel()

		var body ast.Body
		err := matchString(&body, ast.VarTerm("example"), parser.Number("1234"))
		require.NoError(t, err)
		assert.Equal(t, `example == 1234`, str(body))
	})
	t.Run("null", func(t *testing.T) {
		t.Parallel()

		var body ast.Body
		err := matchString(&body, ast.VarTerm("example"), parser.Null{})
		require.NoError(t, err)
		assert.Equal(t, `example == null`, str(body))
	})
	t.Run("in", func(t *testing.T) {
		t.Parallel()

		var body ast.Body
		err := matchString(&body, ast.VarTerm("example"), parser.Object{
			"in": parser.Array{
				parser.String("value1"),
				parser.String("value2"),
				parser.String("value3"),
			},
		})
		require.NoError(t, err)
		assert.Equal(t, `example in ["value1", "value2", "value3"]`, str(body))
	})

	t.Run("not_in", func(t *testing.T) {
		t.Parallel()

		var body ast.Body
		err := matchString(&body, ast.VarTerm("example"), parser.Object{
			"not_in": parser.Array{
				parser.String("value1"),
				parser.String("value2"),
				parser.String("value3"),
			},
		})
		require.NoError(t, err)
		assert.Equal(t, `not example in ["value1", "value2", "value3"]`, str(body))
	})
	t.Run("in with object", func(t *testing.T) {
		t.Parallel()

		var body ast.Body
		err := matchString(&body, ast.VarTerm("example"), parser.Object{
			"in": parser.Array{
				parser.String("admin"),
				parser.String("user"),
			},
		})
		require.NoError(t, err)
		assert.Equal(t, `example in ["admin", "user"]`, str(body))
	})
	t.Run("in with non-array value", func(t *testing.T) {
		t.Parallel()

		var body ast.Body
		err := matchString(&body, ast.VarTerm("example"), parser.Object{
			"in": parser.String("not-an-array"),
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "in matcher requires an array of strings")
	})

	t.Run("not_in with non-array value", func(t *testing.T) {
		t.Parallel()

		var body ast.Body
		err := matchString(&body, ast.VarTerm("example"), parser.Object{
			"not_in": parser.String("not-an-array"),
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not_in matcher requires an array of strings")
	})
}

func TestStringListMatcher(t *testing.T) {
	t.Parallel()

	str := func(x any) string {
		bs := format.MustAst(x)
		return strings.TrimSpace(string(bs))
	}

	t.Run("has", func(t *testing.T) {
		var body ast.Body
		err := matchStringList(&body, ast.VarTerm("example"), parser.Object{
			"has": parser.String("test"),
		})
		require.NoError(t, err)
		assert.Equal(t, `count([true | some v; v = example[_]; v == "test"]) > 0`, str(body))
	})
	t.Run("is", func(t *testing.T) {
		t.Parallel()

		var body ast.Body
		err := matchStringList(&body, ast.VarTerm("example"), parser.Object{
			"is": parser.String("test"),
		})
		require.NoError(t, err)
		assert.Equal(t, `count(example) == 1`+"\n"+`count([true | some v; v = example[_]; v == "test"]) > 0`, str(body))
	})
	t.Run("exclude", func(t *testing.T) {
		t.Parallel()

		var body ast.Body
		err := matchStringList(&body, ast.VarTerm("example"), parser.Object{
			"exclude": parser.String("test"),
		})
		require.NoError(t, err)
		assert.Equal(t, `count([true | some v; v = example[_]; v == "test"]) == 0`, str(body))
	})
	t.Run("string", func(t *testing.T) {
		t.Parallel()

		var body ast.Body
		err := matchStringList(&body, ast.VarTerm("example"), parser.String("test"))
		require.NoError(t, err)
		assert.Equal(t, `count([true | some v; v = example[_]; v == "test"]) > 0`, str(body))
	})
	t.Run("boolean", func(t *testing.T) {
		t.Parallel()

		var body ast.Body
		err := matchStringList(&body, ast.VarTerm("example"), parser.Boolean(true))
		require.NoError(t, err)
		assert.Equal(t, `count([true | some v; v = example[_]; v == true]) > 0`, str(body))
	})
	t.Run("number", func(t *testing.T) {
		t.Parallel()

		var body ast.Body
		err := matchStringList(&body, ast.VarTerm("example"), parser.Number("1234"))
		require.NoError(t, err)
		assert.Equal(t, `count([true | some v; v = example[_]; v == 1234]) > 0`, str(body))
	})
	t.Run("null", func(t *testing.T) {
		t.Parallel()

		var body ast.Body
		err := matchStringList(&body, ast.VarTerm("example"), parser.Null{})
		require.NoError(t, err)
		assert.Equal(t, `count([true | some v; v = example[_]; v == null]) > 0`, str(body))
	})
}
