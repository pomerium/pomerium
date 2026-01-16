package storage

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestFilterExpressionFromStruct(t *testing.T) {
	t.Parallel()

	type M = map[string]any
	type A = []any

	s, err := structpb.NewStruct(M{
		"$and": A{
			M{"a": M{"b": "1"}},
		},
		"c": M{
			"d": M{
				"e": M{
					"$eq": "2",
				},
			},
		},
		"f": A{
			"3", "4", "5",
		},
		"$or": A{
			M{"g": "6"},
			M{"h": "7"},
		},
	})
	require.NoError(t, err)
	expr, err := FilterExpressionFromStruct(s)
	assert.NoError(t, err)
	assert.Equal(t,
		AndFilterExpression{
			MustEqualsFilterExpression("a.b", "1"),
			OrFilterExpression{
				MustEqualsFilterExpression("g", "6"),
				MustEqualsFilterExpression("h", "7"),
			},
			MustEqualsFilterExpression("c.d.e", "2"),
			OrFilterExpression{
				MustEqualsFilterExpression("f", "3"),
				MustEqualsFilterExpression("f", "4"),
				MustEqualsFilterExpression("f", "5"),
			},
		},
		expr)
}
