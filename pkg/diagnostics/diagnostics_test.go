package diagnostics_test

import (
	"crypto/ecdh"
	"crypto/hpke"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/pkg/diagnostics"
)

func TestEncryptBuildInformation(t *testing.T) {
	t.Parallel()

	k1, err := hpke.DHKEM(ecdh.X25519()).GenerateKey()
	require.NoError(t, err)

	info := diagnostics.BuildInformation{
		BuiltAt:         time.Date(2026, time.November, 19, 15, 11, 0, 0, time.UTC),
		ComputedAt:      time.Date(2026, time.November, 19, 15, 12, 0, 0, time.UTC),
		EnvoyLicense:    "envoy-license",
		EnvoyVersion:    "envoy-version",
		PomeriumLicense: "pomerium-license",
		PomeriumVersion: "pomerium-version",
	}

	data, err := diagnostics.EncryptBuildInformation(0x01, k1.PublicKey(), info)
	assert.NoError(t, err)
	decrypted, err := diagnostics.DecryptBuildInformation(func(_ byte, _, _, _ uint16) (hpke.PrivateKey, error) {
		return k1, nil
	}, data)
	assert.NoError(t, err)
	assert.Equal(t, &info, decrypted)
}

func TestPadsInfo(t *testing.T) {
	t.Parallel()

	k1, err := hpke.DHKEM(ecdh.X25519()).GenerateKey()
	require.NoError(t, err)

	data, err := diagnostics.EncryptBuildInformation(0x01, k1.PublicKey(), diagnostics.BuildInformation{})
	assert.NoError(t, err)
	assert.Greater(t, len(data), 1_024)
}
