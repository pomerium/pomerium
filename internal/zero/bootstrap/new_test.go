package bootstrap_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/internal/zero/bootstrap"
)

func TestConfigDeterministic(t *testing.T) {
	secret := []byte("secret")

	src, err := bootstrap.New(secret, nil, nil, nil)
	require.NoError(t, err)
	cfg := src.GetConfig()
	require.NotNil(t, cfg)

	// test that the config is valid
	require.NoError(t, cfg.Options.Validate())

	// test that the config is deterministic
	src2, err := bootstrap.New(secret, nil, nil, nil)
	require.NoError(t, err)

	cfg2 := src2.GetConfig()
	require.NotNil(t, cfg2)

	require.Equal(t, cfg.Options, cfg2.Options)
}

// TestNewSetsEnvoyAdminInternalAddress guards against a regression where the
// zero bootstrap config was built via new(config.Config) and never had its
// EnvoyAdminInternalAddress defaulted. The empty address caused EnvoyAddress()
// to hit its panic branch ("unsupported internal address") when the control
// plane built the envoy admin cluster, crash-looping the zero data plane.
func TestNewSetsEnvoyAdminInternalAddress(t *testing.T) {
	src, err := bootstrap.New([]byte("secret"), nil, nil, nil)
	require.NoError(t, err)
	cfg := src.GetConfig()
	require.NotNil(t, cfg)

	require.NotEmpty(t, cfg.EnvoyAdminInternalAddress.URL.Scheme,
		"EnvoyAdminInternalAddress must be defaulted in zero bootstrap config")
	require.NotPanics(t, func() {
		_ = cfg.EnvoyAdminInternalAddress.EnvoyAddress()
	}, "building the envoy admin address must not panic")
}
