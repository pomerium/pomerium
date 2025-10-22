package postgres

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/pomerium/pomerium/pkg/storage"
)

func TestAddFilterExpressionToQuery(t *testing.T) {
	t.Parallel()

	query := ""
	args := []any{}
	addFilterExpressionToQuery(&query, &args, storage.AndFilterExpression{
		storage.OrFilterExpression{
			storage.EqualsFilterExpression{
				Fields: []string{"id"},
				Value:  "v1",
			},
			storage.EqualsFilterExpression{
				Fields: []string{"$index"},
				Value:  "v2",
			},
			storage.EqualsFilterExpression{
				Fields: []string{"$index"},
				Value:  "10.0.0.0/8",
			},
		},
		storage.EqualsFilterExpression{
			Fields: []string{"type"},
			Value:  "v3",
		},
	})
	assert.Equal(t, "( ( pomerium.records.id = $1 OR  false  OR pomerium.records.index_cidr >>= $2 ) AND pomerium.records.type = $3 )", query)
	assert.Equal(t, []any{"v1", "10.0.0.0/8", "v3"}, args)
}
