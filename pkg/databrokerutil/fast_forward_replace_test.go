package databrokerutil

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"

	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
)

type recordReplacer interface {
	ReplaceRecords(ctx context.Context, serverVersion uint64, records []*databrokerpb.Record)
}

type mockReplacingFF struct {
	mockFF
	replace chan []*databrokerpb.Record
}

func (ff *mockReplacingFF) ReplaceRecords(_ context.Context, _ uint64, records []*databrokerpb.Record) {
	ff.replace <- records
}

// TestFastForward_ReplaceRecords covers the handler a syncer gets when it is
// created with WithFastForward, as the config syncers are. A replacement must
// reach the wrapped handler as one call.
func TestFastForward_ReplaceRecords(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	m := &mockReplacingFF{
		clear:   make(chan struct{}, 1),
		update:  make(chan uint64, 1),
		replace: make(chan []*databrokerpb.Record, 1),
	}
	f := newFastForwardHandler(ctx, noop.NewTracerProvider(), "test", m)
	replacer, ok := f.(recordReplacer)
	require.True(t, ok, "the fast-forward handler cannot replace records in one step")

	replacer.ReplaceRecords(ctx, 1, []*databrokerpb.Record{{Type: "t", Id: "1"}, {Type: "t", Id: "2"}})
	select {
	case <-ctx.Done():
		t.Fatal("the replacement never reached the handler")
	case <-m.clear:
		t.Fatal("the replacement reached the handler as a clear")
	case records := <-m.replace:
		assert.Len(t, records, 2)
	}
}

// TestFastForward_EmptyReplaceUpdatesPlainHandler covers a re-sync that
// returns no records, delivered through the fast-forward handler to a handler
// that cannot replace records. The handler must still get UpdateRecords with
// the new server version, as it does without fast-forward.
func TestFastForward_EmptyReplaceUpdatesPlainHandler(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()

	m := &mockFF{clear: make(chan struct{}, 1), update: make(chan uint64, 1)}
	f := newFastForwardHandler(ctx, noop.NewTracerProvider(), "test", m)
	replacer, ok := f.(recordReplacer)
	require.True(t, ok)

	replacer.ReplaceRecords(ctx, 7, nil)

	sv, err := m.getUpdate(ctx)
	require.NoError(t, err, "the handler never got UpdateRecords")
	assert.Equal(t, uint64(7), sv)
}
