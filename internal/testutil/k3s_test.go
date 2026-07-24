package testutil_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/internal/testutil"
)

func TestK3sImageForK8sModuleVersion(t *testing.T) {
	t.Parallel()

	ok := map[string]string{
		"v0.36.0": "rancher/k3s:v1.36.0-k3s1",
		"v0.36.1": "rancher/k3s:v1.36.0-k3s1", // patch is normalized to .0
		"v0.37.4": "rancher/k3s:v1.37.0-k3s1",
	}
	for in, want := range ok {
		got, err := testutil.K3sImageForK8sModuleVersion(in)
		require.NoError(t, err, in)
		assert.Equal(t, want, got, in)
	}

	for _, bad := range []string{"v1.2.3", "0.36.1", "", "v0.", "v0.36"} {
		_, err := testutil.K3sImageForK8sModuleVersion(bad)
		assert.Error(t, err, bad)
	}
}
