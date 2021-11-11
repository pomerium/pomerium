package cli

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestListener(t *testing.T) {
	l := newListenerStatus()
	var called bool

	err := l.SetListening("a", func() { called = true }, "addr")
	require.NoError(t, err)

	status := l.GetListenerStatus("a")
	if assert.NotNil(t, status.ListenAddr) {
		assert.Equal(t, "addr", *status.ListenAddr)
	}
	assert.True(t, status.Listening)
	assert.Nil(t, status.LastError)

	assert.NoError(t, l.SetNotListening("a"))
	assert.True(t, called)
}
