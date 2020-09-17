package azure

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGroupLookup(t *testing.T) {
	gl := newGroupLookup()

	gl.addGroup("g1", []string{"g11", "g12", "g13"}, []string{"u1"})
	gl.addGroup("g11", []string{"g111"}, nil)
	gl.addGroup("g111", nil, []string{"u2"})

	assert.Equal(t, []string{"u1", "u2"}, gl.getUserIDs())
	assert.Equal(t, []string{"g1", "g11", "g111"}, gl.getGroupIDsForUser("u2"))

	t.Run("cycle protection", func(t *testing.T) {
		gl.addGroup("g12", []string{"g1"}, nil)

		assert.Equal(t, []string{"u1", "u2"}, gl.getUserIDs())
		assert.Equal(t, []string{"g1", "g11", "g111", "g12"}, gl.getGroupIDsForUser("u2"))
	})
}
