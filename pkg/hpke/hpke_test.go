package hpke

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSeal(t *testing.T) {
	k1, err := GeneratePrivateKey()
	require.NoError(t, err)
	k2, err := GeneratePrivateKey()
	require.NoError(t, err)

	sealed, err := Seal(k1, k2.PublicKey(), []byte("HELLO WORLD"))
	assert.NoError(t, err)
	assert.NotEmpty(t, sealed)

	message, err := Open(k2, k1.PublicKey(), sealed)
	assert.NoError(t, err)
	assert.Equal(t, []byte("HELLO WORLD"), message)
}

func TestDerivePrivateKey(t *testing.T) {
	k1a := DerivePrivateKey([]byte("KEY 1"))
	k1b := DerivePrivateKey([]byte("KEY 1"))
	k2 := DerivePrivateKey([]byte("KEY 2"))

	assert.Equal(t, k1a.String(), k1b.String())
	assert.NotEqual(t, k1a.String(), k2.String())
}
