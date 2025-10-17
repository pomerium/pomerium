package postgres

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/pomerium/pomerium/pkg/storage"
)

func TestAddFilterExpressionToQuery(t *testing.T) {
	t.Parallel()

	query := ""
	args := []any{}
	err := addFilterExpressionToQuery(&query, &args, storage.AndFilterExpression{
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
		storage.EqualsFilterExpression{
			Fields: []string{"some_other", "field"},
			Value:  "v4",
		},
	})
	assert.NoError(t, err)
	assert.Equal(t, strings.Join([]string{
		"(",
		"(",
		"pomerium.records.id = $1",
		"OR ",
		"false ",
		"OR",
		"pomerium.records.index_cidr >>= $2",
		")",
		"AND",
		"pomerium.records.type = $3",
		"AND",
		"((jsonb_extract_path_text(pomerium.records.data,$4,$5) = $6)",
		"OR",
		"(jsonb_extract_path_text(pomerium.records.data,$7,$8) = $9))",
		")",
	}, " "), query)
	assert.Equal(t, []any{
		"v1",
		"10.0.0.0/8",
		"v3",
		"some_other", "field", "v4",
		"someOther", "field", "v4",
	}, args)
}
