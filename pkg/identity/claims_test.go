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

func TestFlattenedClaims_ToPB_JSONNumber(t *testing.T) {
	// claims decoded with UseNumber (as in internal/jwtutil) hold json.Number
	// values, which must be preserved as numbers rather than nulls
	pb := FlattenedClaims{"exp": {json.Number("1754071824")}}.ToPB()
	assert.Equal(t, float64(1754071824), pb["exp"].GetValues()[0].GetNumberValue())
}
