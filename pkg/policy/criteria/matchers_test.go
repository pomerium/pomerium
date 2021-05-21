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
	str := func(x interface{}) string {
		bs := format.MustAst(x)
		return strings.TrimSpace(string(bs))
	}

	t.Run("contains", func(t *testing.T) {
		var body ast.Body
		err := matchString(&body, ast.VarTerm("example"), parser.Object{
			"contains": parser.String("test"),
		})
		require.NoError(t, err)
		assert.Equal(t, `contains(example, "test")`, str(body))
	})
	t.Run("ends_with", func(t *testing.T) {
		var body ast.Body
		err := matchString(&body, ast.VarTerm("example"), parser.Object{
			"ends_with": parser.String("test"),
		})
		require.NoError(t, err)
		assert.Equal(t, `endswith(example, "test")`, str(body))
	})
	t.Run("is", func(t *testing.T) {
		var body ast.Body
		err := matchString(&body, ast.VarTerm("example"), parser.Object{
			"is": parser.String("test"),
		})
		require.NoError(t, err)
		assert.Equal(t, `example == "test"`, str(body))
	})
	t.Run("starts_with", func(t *testing.T) {
		var body ast.Body
		err := matchString(&body, ast.VarTerm("example"), parser.Object{
			"starts_with": parser.String("test"),
		})
		require.NoError(t, err)
		assert.Equal(t, `startswith(example, "test")`, str(body))
	})
}

func TestStringListMatcher(t *testing.T) {
	str := func(x interface{}) string {
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
}
