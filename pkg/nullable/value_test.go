package nullable_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v3"

	"github.com/pomerium/pomerium/pkg/nullable"
)

func TestUnmarshalJSON(t *testing.T) {
	t.Parallel()

	var v nullable.Value[int]

	assert.NoError(t, json.Unmarshal([]byte(`null`), &v))
	assert.Equal(t, nullable.NewValue(false, 0), v)

	assert.NoError(t, json.Unmarshal([]byte(`27`), &v))
	assert.Equal(t, nullable.NewValue(true, 27), v)
}

func TestUnmarshalYAML(t *testing.T) {
	t.Parallel()

	var v nullable.Value[int]

	assert.NoError(t, yaml.Unmarshal([]byte(`null`), &v))
	assert.Equal(t, nullable.NewValue(false, 0), v)

	assert.NoError(t, yaml.Unmarshal([]byte(`27`), &v))
	assert.Equal(t, nullable.NewValue(true, 27), v)
}
