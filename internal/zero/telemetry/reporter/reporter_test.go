package reporter

import (
	"testing"

	"github.com/hashicorp/go-set/v3"
	"github.com/stretchr/testify/assert"
)

func Test_getResource(t *testing.T) {
	t.Parallel()

	r := getResource()
	ks := set.New[string](0)
	for _, attr := range r.Attributes() {
		ks.Insert(string(attr.Key))
	}
	assert.True(t, ks.Contains("pomerium.config.version"))
	assert.True(t, ks.Contains("pomerium.envoy.version"))
	assert.True(t, ks.Contains("pomerium.mcp.version"))
	assert.True(t, ks.Contains("pomerium.ssh.version"))
}
