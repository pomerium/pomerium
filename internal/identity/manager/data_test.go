package manager

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUser_UnmarshalJSON(t *testing.T) {
	var u User
	err := json.Unmarshal([]byte(`{
	"name": "joe",
	"email": "joe@test.com",
	"groups": ["a","b","c"]
}`), &u)
	assert.NoError(t, err)
	assert.NotNil(t, u.User)
	assert.Equal(t, "joe", u.User.Name)
	assert.Equal(t, "joe@test.com", u.User.Email)
	assert.Equal(t, []string{"a", "b", "c"}, u.User.Groups)
}
