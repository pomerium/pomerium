package cli

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestListener(t *testing.T) {
	l := newListenerStatus()
	var called bool

	l.SetListening("a", func() { called = true }, "addr")
	addr, listening := l.IsListening("a")
	assert.Equal(t, "addr", addr)
	assert.True(t, listening)

	assert.NoError(t, l.SetNotListening("a"))
	assert.True(t, called)
}
