package bootstrap_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/internal/zero/bootstrap"
)

func TestConfigDeterministic(t *testing.T) {
	secret := []byte("secret")

	src, err := bootstrap.New(secret)
	require.NoError(t, err)
	cfg := src.GetConfig()
	require.NotNil(t, cfg)

	// test that the config is valid
	require.NoError(t, cfg.Options.Validate())

	// test that the config is deterministic
	src2, err := bootstrap.New(secret)
	require.NoError(t, err)

	cfg2 := src2.GetConfig()
	require.NotNil(t, cfg2)

	require.Equal(t, cfg.Options, cfg2.Options)
}
