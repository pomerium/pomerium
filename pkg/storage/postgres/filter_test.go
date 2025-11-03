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
			storage.EqualsFilterExpression{
				Fields: []string{"session_id"},
				Value:  "sessionA",
			},
		},
		storage.EqualsFilterExpression{
			Fields: []string{"type"},
			Value:  "v3",
		},
	})
	expected := "( ( pomerium.records.id = $1 OR  false  OR pomerium.records.index_cidr >>= $2 OR (jsonb_extract_path_text(pomerium.records.data,$3) = $4) ) AND pomerium.records.type = $5 )"
	assert.Equal(t, expected, query)
	assert.Equal(t, []any{"v1", "10.0.0.0/8", "sessionId", "sessionA", "v3"}, args)
}
