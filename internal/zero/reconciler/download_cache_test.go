package reconciler_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/internal/zero/reconciler"
	zero_sdk "github.com/pomerium/pomerium/pkg/zero"
)

func TestCacheEntryProto(t *testing.T) {
	t.Parallel()

	original := reconciler.BundleCacheEntry{
		DownloadConditional: zero_sdk.DownloadConditional{
			ETag:         "etag value",
			LastModified: "2009-02-13 18:31:30 -0500 EST",
		},
		RecordTypes: []string{"one", "two"},
	}
	originalProto, err := original.ToAny()
	require.NoError(t, err)
	var unmarshaled reconciler.BundleCacheEntry
	err = unmarshaled.FromAny(originalProto)
	require.NoError(t, err)
	assert.True(t, original.Equals(&unmarshaled))
}
