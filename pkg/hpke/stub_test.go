package hpke_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/pkg/hpke"
)

func TestStubFetcher(t *testing.T) {
	t.Parallel()

	hpkePrivateKey, err := hpke.GeneratePrivateKey()
	require.NoError(t, err)

	expected := hpkePrivateKey.PublicKey()

	f := hpke.NewStubKeyFetcher(expected)

	actual, err := f.FetchPublicKey(context.Background())
	require.NoError(t, err)
	assert.Equal(t, expected.String(), actual.String())
}
