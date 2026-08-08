package providertest

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/pkg/secrets/ref"
)

// The Fake must honour the provider.Watcher contract ("until ctx is done or
// the returned stop func is called") so that a test which stops a watch by
// cancelling its context does not pass against the Fake while diverging from
// the real file provider.
func TestFakeWatchHonoursContextCancel(t *testing.T) {
	t.Parallel()

	f := New("test")
	r, err := ref.Parse("test:///key")
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	var count atomic.Int64
	stop, err := f.Watch(ctx, r, func() { count.Add(1) })
	require.NoError(t, err)
	defer stop()

	cancel()
	// context.AfterFunc runs teardown on its own goroutine, so poll until a
	// trigger stops reaching the callback. Without the ctx wiring every
	// trigger increments the counter and this never converges.
	assert.Eventually(t, func() bool {
		before := count.Load()
		f.TriggerWatch(r.FetchKey())
		return count.Load() == before
	}, 3*time.Second, 10*time.Millisecond, "notify still fires after ctx was cancelled")
}
