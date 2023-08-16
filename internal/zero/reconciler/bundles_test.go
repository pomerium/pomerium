package reconciler_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/internal/zero/reconciler"
)

func TestSet(t *testing.T) {
	t.Parallel()

	b := &reconciler.Bundles{}
	b.Set([]string{"bundle1", "bundle2"})

	id1, ok1 := b.GetNextBundleToSync()
	id2, ok2 := b.GetNextBundleToSync()

	assert.True(t, ok1, "Expected bundle1 to be set")
	assert.Equal(t, "bundle1", id1)
	assert.True(t, ok2, "Expected bundle2 to be set")
	assert.Equal(t, "bundle2", id2)

	id3, ok3 := b.GetNextBundleToSync()
	assert.False(t, ok3, "Expected no more bundles to sync")
	assert.Empty(t, id3)
}

func TestMarkForSync(t *testing.T) {
	t.Parallel()

	b := &reconciler.Bundles{}
	b.Set([]string{"bundle1", "bundle2"})

	b.MarkForSync("bundle2")
	id1, ok1 := b.GetNextBundleToSync()

	assert.True(t, ok1, "Expected bundle1 to be marked for sync")
	assert.Equal(t, "bundle1", id1)

	b.MarkForSync("bundle3")
	id2, ok2 := b.GetNextBundleToSync()
	id3, ok3 := b.GetNextBundleToSync()

	assert.True(t, ok2, "Expected bundle2 to be marked for sync")
	assert.Equal(t, "bundle2", id2)
	assert.True(t, ok3, "Expected bundle3 to be marked for sync")
	assert.Equal(t, "bundle3", id3)
}

func TestMarkForSyncLater(t *testing.T) {
	t.Parallel()

	b := &reconciler.Bundles{}
	b.Set([]string{"bundle1", "bundle2", "bundle3"})

	id1, ok1 := b.GetNextBundleToSync()
	b.MarkForSyncLater("bundle1")
	id2, ok2 := b.GetNextBundleToSync()
	id3, ok3 := b.GetNextBundleToSync()
	id4, ok4 := b.GetNextBundleToSync()
	id5, ok5 := b.GetNextBundleToSync()

	assert.True(t, ok1, "Expected bundle1 to be marked for sync")
	assert.Equal(t, "bundle1", id1)
	assert.True(t, ok2, "Expected bundle2 to be marked for sync")
	assert.Equal(t, "bundle2", id2)
	assert.True(t, ok3, "Expected bundle3 to be marked for sync")
	assert.Equal(t, "bundle3", id3)
	assert.True(t, ok4, "Expected bundle1 to be marked for sync")
	assert.Equal(t, "bundle1", id4)
	assert.False(t, ok5, "Expected no more bundles to sync")
	assert.Empty(t, id5)

}

func TestGetNextBundleToSync(t *testing.T) {
	t.Parallel()

	b := &reconciler.Bundles{}
	b.Set([]string{"bundle1", "bundle2"})

	id1, ok1 := b.GetNextBundleToSync()
	id2, ok2 := b.GetNextBundleToSync()
	id3, ok3 := b.GetNextBundleToSync()

	assert.True(t, ok1, "Expected bundle1 to be retrieved for sync")
	assert.Equal(t, "bundle1", id1)
	assert.True(t, ok2, "Expected bundle2 to be retrieved for sync")
	assert.Equal(t, "bundle2", id2)
	require.False(t, ok3, "Expected no more bundles to sync")
	assert.Empty(t, id3)
}

func TestConcurrency(t *testing.T) {
	t.Parallel()

	b := &reconciler.Bundles{}
	b.Set([]string{"bundle1", "bundle2", "bundle3"})

	ch := make(chan bool, 3)

	go func() {
		b.MarkForSync("bundle4")
		ch <- true
	}()

	go func() {
		b.MarkForSyncLater("bundle2")
		ch <- true
	}()

	go func() {
		b.GetNextBundleToSync()
		ch <- true
	}()

	for i := 0; i < 3; i++ {
		<-ch
	}
}
