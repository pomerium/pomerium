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
			EqualsFilterExpression{
				Fields: []string{"a", "b"},
				Value:  "1",
			},
			OrFilterExpression{
				EqualsFilterExpression{
					Fields: []string{"g"},
					Value:  "6",
				},
				EqualsFilterExpression{
					Fields: []string{"h"},
					Value:  "7",
				},
			},
			EqualsFilterExpression{
				Fields: []string{"c", "d", "e"},
				Value:  "2",
			},
			OrFilterExpression{
				EqualsFilterExpression{
					Fields: []string{"f"},
					Value:  "3",
				},
				EqualsFilterExpression{
					Fields: []string{"f"},
					Value:  "4",
				},
				EqualsFilterExpression{
					Fields: []string{"f"},
					Value:  "5",
				},
			},
		},
		expr)
}
