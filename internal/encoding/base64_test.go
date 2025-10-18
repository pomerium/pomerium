package encoding

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDecodeBase64OrJSON(t *testing.T) {
	t.Parallel()

	var obj struct {
		X string `json:"x"`
	}
	err := DecodeBase64OrJSON(`    {"x": "y"}    `, &obj)
	assert.NoError(t, err)
	assert.Equal(t, "y", obj.X)

	err = DecodeBase64OrJSON(`    eyJ4IjoieiJ9Cg==    `, &obj)
	assert.NoError(t, err)
	assert.Equal(t, "z", obj.X)
}
