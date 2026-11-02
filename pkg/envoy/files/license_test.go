package files_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/pomerium/pomerium/pkg/envoy/files"
)

func TestEmbeddedLicenseIdentifier(t *testing.T) {
	id, err := files.EmbeddedEnvoyLicenseIdentifier()
	if err != nil {
		assert.ErrorIs(t, err, files.ErrNoLicenseFound)
	} else {
		assert.Truef(t, id == "Apache-2.0" || id == "LicenseRef-Pomerium-Community-Edition-1.0",
			"unexpected license identifier: %s", id)
	}
}
