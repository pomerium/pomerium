package inmemory

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/iterutil"
	"github.com/pomerium/pomerium/pkg/storage"
	"github.com/pomerium/pomerium/pkg/storage/storagetest"
)

func TestBackend(t *testing.T) {
	t.Parallel()

	backend := New()
	t.Cleanup(func() { backend.Close() })

	storagetest.TestBackend(t, backend)
}

func TestIndexing(t *testing.T) {
	t.Parallel()
	backend := New()
	t.Cleanup(func() { backend.Close() })
	storagetest.TestIndexing(t, backend)
}

func TestSyncOldRecords(t *testing.T) {
	t.Parallel()

	backend := New()
	t.Cleanup(func() { backend.Close() })

	storagetest.TestSyncOldRecords(t, backend)
}

func TestExpiry(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	backend := New()
	defer func() { _ = backend.Close() }()
	n := 1000
	for i := range n {
		sv, err := backend.Put(ctx, []*databroker.Record{{
			Type: "TYPE",
			Id:   fmt.Sprint(i),
		}})
		assert.NoError(t, err)
		assert.Equal(t, backend.serverVersion, sv)
	}
	seq := backend.Sync(ctx, "", backend.serverVersion, 0, false)
	records, err := iterutil.CollectWithError(seq)
	require.NoError(t, err)
	require.Len(t, records, n+1)

	backend.Clean(ctx, storage.CleanOptions{
		RemoveRecordChangesBefore: time.Now().Add(time.Second),
	})

	cnt := 0
	for _, err := range backend.Sync(ctx, "", backend.serverVersion, 0, false) {
		assert.ErrorIs(t, err, storage.ErrInvalidRecordVersion)
		cnt++
	}
	assert.Greater(t, cnt, 0)
}

func TestFilter(t *testing.T) {
	t.Parallel()

	backend := New()
	t.Cleanup(func() { _ = backend.Close() })

	storagetest.TestFilter(t, backend)
}

func TestClear(t *testing.T) {
	t.Parallel()

	backend := New()
	t.Cleanup(func() { _ = backend.Close() })

	storagetest.TestClear(t, backend)
}

func BenchmarkPut(b *testing.B) {
	backend := New()
	defer func() { _ = backend.Close() }()
	storagetest.BenchmarkPut(b, backend)
}
