package databroker

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/storage"
)

// failOnceSetOptionsBackend fails the first SetOptions for one record type and
// then behaves normally, standing in for a transient backend error.
type failOnceSetOptionsBackend struct {
	storage.Backend

	failType string

	mu     sync.Mutex
	n      int
	failed bool
}

func (b *failOnceSetOptionsBackend) SetOptions(
	ctx context.Context, recordType string, options *databrokerpb.Options,
) error {
	if recordType != b.failType {
		return b.Backend.SetOptions(ctx, recordType, options)
	}

	b.mu.Lock()
	b.n++
	first := !b.failed
	b.failed = true
	b.mu.Unlock()

	if first {
		return errors.New("induced SetOptions failure")
	}
	return b.Backend.SetOptions(ctx, recordType, options)
}

func (b *failOnceSetOptionsBackend) attempts() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.n
}

// TestOnConfigChange_AgenticRunTTLRetriedAfterSetOptionsFailure pins that a TTL
// which the backend refused is retried.
//
// OnConfigChange only re-registers the record options when the computed TTL
// differs from the one it last cached. Caching before the backend has accepted
// it means a transient failure is remembered as success: every later reload of
// the same configuration compares equal and skips the update, so record cleanup
// keeps running on the stale TTL until the backend is rebuilt for some
// unrelated reason.
func TestOnConfigChange_AgenticRunTTLRetriedAfterSetOptionsFailure(t *testing.T) {
	t.Parallel()

	srv := NewBackendServer(noop.NewTracerProvider()).(*backendServer)
	t.Cleanup(srv.Stop)

	base := &config.Options{
		DataBroker: config.DataBrokerOptions{StorageType: config.StorageInMemoryName},
		SharedKey:  cryptutil.NewBase64Key(),
	}
	srv.OnConfigChange(t.Context(), config.New(base))

	// The backend is built lazily, so force it into existence before wrapping it.
	backend, err := srv.getBackend(t.Context())
	require.NoError(t, err)

	failing := &failOnceSetOptionsBackend{
		Backend:  backend,
		failType: "type.googleapis.com/oauth21.AgenticRun",
	}
	srv.mu.Lock()
	srv.backend = failing
	srv.mu.Unlock()

	// A new idle timeout, so the TTL genuinely changes.
	changed := *base
	changed.AgenticRunIdleTimeout = 72 * time.Hour
	cfg := config.New(&changed)

	srv.OnConfigChange(t.Context(), cfg)
	require.Equal(t, 1, failing.attempts(), "the new TTL must be pushed to the backend")

	// The same configuration again: nothing changed, but nothing was applied
	// either, so the update is still outstanding.
	srv.OnConfigChange(t.Context(), cfg)
	assert.Equal(t, 2, failing.attempts(),
		"a TTL the backend refused must be retried on the next config update")
}
