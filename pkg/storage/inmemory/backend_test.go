package inmemory

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/storage"
	"github.com/pomerium/pomerium/pkg/storage/storagetest"
)

func TestBackend(t *testing.T) {
	t.Parallel()

	backend := New()
	t.Cleanup(func() { backend.Close() })

	storagetest.TestBackend(t, backend)
}

func TestExpiry(t *testing.T) {
	ctx := t.Context()
	backend := New(WithExpiry(0))
	defer func() { _ = backend.Close() }()

	for i := range 1000 {
		sv, err := backend.Put(ctx, []*databroker.Record{{
			Type: "TYPE",
			Id:   fmt.Sprint(i),
		}})
		assert.NoError(t, err)
		assert.Equal(t, backend.serverVersion, sv)
	}
	seq := backend.Sync(ctx, "", backend.serverVersion, 0, false)
	records, err := storage.RecordIteratorToList(seq)
	require.NoError(t, err)
	require.Len(t, records, 1000)

	backend.removeChangesBefore(time.Now().Add(time.Second))

	seq = backend.Sync(ctx, "", backend.serverVersion, 0, false)
	records, err = storage.RecordIteratorToList(seq)
	require.NoError(t, err)
	require.Len(t, records, 0)
}
