package resolver

import (
	"context"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLookupDuringInitialFetch(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		reg, fake := testFakeRegistry(t)
		fk := fkOf(t, "file:///a")
		fake.SetValue(fk, "v1")
		fake.Block(fk) // first fetch blocks

		r := newTestResolver(t, reg)
		defer r.Close()

		r.Apply(context.Background(), buildScope(t, reg, bind(t, "tok", "file:///a")))
		synctest.Wait() // loop is blocked inside the first provider.Fetch

		// The resolver never gates callers on fetch completion: the binding is
		// known but not yet resolved.
		got := r.Lookup("tok")
		assert.True(t, got.Found)
		assert.Equal(t, StateFailed, got.State)
		assert.Equal(t, "", got.Value)

		fake.Release(fk)
		synctest.Wait()

		got = r.Lookup("tok")
		assert.Equal(t, StateFresh, got.State)
		assert.Equal(t, "v1", got.Value)
	})
}

func TestCloseStops(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		reg, fake := testFakeRegistry(t)
		fk := fkOf(t, "file:///a")
		fake.SetValue(fk, "v1")

		r := newTestResolver(t, reg)
		r.Apply(context.Background(), buildScope(t, reg, bind(t, "tok", "file:///a")))
		synctest.Wait()
		require.Equal(t, "v1", r.Lookup("tok").Value)

		r.Close()
		r.Close() // idempotent
		synctest.Wait()

		// No further fetches after Close.
		before := fake.FetchCount(fk)
		advance(10 * time.Minute)
		assert.Equal(t, before, fake.FetchCount(fk))

		// Reads still serve the last snapshot.
		assert.Equal(t, "v1", r.Lookup("tok").Value)
	})
}
