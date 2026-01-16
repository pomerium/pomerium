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
	addFilterExpressionToQuery(&query, &args,
		storage.NotFilterExpression{
			FilterExpression: storage.AndFilterExpression{
				storage.OrFilterExpression{
					storage.MustEqualsFilterExpression("id", "v1"),
					storage.MustEqualsFilterExpression("$index", "v2"),
					storage.MustEqualsFilterExpression("$index", "10.0.0.0/8"),
					storage.MustEqualsFilterExpression("session_id", "sessionA"),
				},
				storage.MustEqualsFilterExpression("type", "v3"),
			},
		})
	expected := "NOT ( ( ( pomerium.records.id = $1 OR  false  OR pomerium.records.index_cidr >>= $2 OR (jsonb_extract_path_text(pomerium.records.data,$3) = $4) ) AND pomerium.records.type = $5 ) )"
	assert.Equal(t, expected, query)
	assert.Equal(t, []any{"v1", "10.0.0.0/8", "sessionId", "sessionA", "v3"}, args)
}
