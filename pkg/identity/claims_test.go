package identity

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestClaims_Flatten(t *testing.T) {
	var claims Claims
	_ = json.Unmarshal([]byte(`
		{
			"a": {
				"aa": {
					"aaa": 12345
				},
				"ab": [1, 2, 3, 4, 5]
			}
		}
	`), &claims)

	flattened := claims.Flatten()
	assert.Equal(t, FlattenedClaims{
		"a.aa.aaa": {12345.0},
		"a.ab":     {1.0, 2.0, 3.0, 4.0, 5.0},
	}, flattened)
}
