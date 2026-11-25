package files_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/pomerium/pomerium/pkg/diagnostics"
	"github.com/pomerium/pomerium/pkg/envoy/files"
)

func TestDiagnosticsBuildInformation(t *testing.T) {
	t.Parallel()

	license, _ := files.EmbeddedEnvoyLicenseIdentifier()
	info := diagnostics.ComputeBuildInformation()
	assert.Equal(t, files.Lockfile().Version, info.EnvoyVersion)
	assert.Equal(t, license, info.EnvoyLicense)
}
