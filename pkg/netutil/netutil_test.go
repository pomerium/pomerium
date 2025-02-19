package netutil_test

import (
	"testing"

	"github.com/minio/minio-go/v7/pkg/set"
	"github.com/stretchr/testify/assert"

	"github.com/pomerium/pomerium/pkg/netutil"
)

func TestAllocatePorts(t *testing.T) {
	t.Parallel()

	seen := set.NewStringSet()
	for i := 0; i < 100; i++ {
		ports, err := netutil.AllocatePorts(3)
		assert.NoError(t, err)
		for _, p := range ports {
			assert.False(t, seen.Contains(p), "should not re-use ports")
			seen.Add(p)
		}
	}
}
