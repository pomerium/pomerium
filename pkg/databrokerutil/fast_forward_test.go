package databrokerutil

import (
	"context"
	"math/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"

	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
)

type mockFF struct {
	clear  chan struct{}
	update chan uint64
}

func (ff *mockFF) ClearRecords(_ context.Context) {
	ff.clear <- struct{}{}
}

func (ff *mockFF) UpdateRecords(_ context.Context, sv uint64, _ []*databrokerpb.Record) {
	time.Sleep(time.Millisecond * time.Duration(rand.Intn(5)))
	ff.update <- sv
}

func (ff *mockFF) GetDataBrokerServiceClient() databrokerpb.DataBrokerServiceClient {
	return nil
}

func (ff *mockFF) getUpdate(ctx context.Context) (uint64, error) {
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case sv := <-ff.update:
		return sv, nil
	}
}

func TestFastForward(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(t.Context(), time.Second*15)
	defer cancel()

	m := &mockFF{
		clear:  make(chan struct{}),
		update: make(chan uint64),
	}

	f := newFastForwardHandler(ctx, noop.NewTracerProvider(), "test", m)

	for x := range 10 {
		n := rand.Intn(10) + 1
		for i := 1; i <= n; i++ {
			f.UpdateRecords(ctx, uint64(i), nil)
		}

		var prev uint64
		assert.Eventually(t, func() bool {
			sv, err := m.getUpdate(ctx)
			require.NoError(t, err)
			assert.Less(t, prev, sv)
			prev = sv
			t.Log(x, sv)
			return int(sv) == n
		}, time.Second, time.Millisecond*10)

		f.ClearRecords(ctx)
		select {
		case <-ctx.Done():
			t.Error("timed out")
		case <-m.clear:
		}
	}
}

// blockingFF blocks in its first UpdateRecords call until released, so that
// the commands enqueued in the meantime are still pending when it is free.
type blockingFF struct {
	calls   chan string
	blocked chan struct{}
	release chan struct{}
	busy    bool
}

func (ff *blockingFF) ClearRecords(_ context.Context) {
	ff.calls <- "ClearRecords"
}

func (ff *blockingFF) UpdateRecords(_ context.Context, _ uint64, _ []*databrokerpb.Record) {
	if !ff.busy {
		ff.busy = true
		close(ff.blocked)
		<-ff.release
		return
	}
	ff.calls <- "UpdateRecords"
}

func (ff *blockingFF) GetDataBrokerServiceClient() databrokerpb.DataBrokerServiceClient {
	return nil
}

// TestFastForward_ClearBeforeMergedUpdate covers a re-sync that arrives while
// the handler is still applying an earlier update. The re-sync clears the
// records and then delivers the re-fetched ones, and both are still pending
// when the handler is free. The handler must be cleared before it gets the
// re-fetched records, otherwise records that no longer exist stay.
func TestFastForward_ClearBeforeMergedUpdate(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(t.Context(), time.Second*10)
	defer cancel()

	m := &blockingFF{
		calls:   make(chan string, 2),
		blocked: make(chan struct{}),
		release: make(chan struct{}),
	}
	f := newFastForwardHandler(ctx, noop.NewTracerProvider(), "test", m)

	// the handler is busy applying an earlier update
	f.UpdateRecords(ctx, 1, nil)
	select {
	case <-ctx.Done():
		t.Fatal("timed out")
	case <-m.blocked:
	}

	// a re-sync clears the records and delivers the re-fetched ones
	f.ClearRecords(ctx)
	f.UpdateRecords(ctx, 2, []*databrokerpb.Record{{Type: "t", Id: "1"}})
	close(m.release)

	next := func() string {
		select {
		case <-ctx.Done():
			t.Fatal("timed out")
		case call := <-m.calls:
			return call
		}
		return ""
	}
	require.Equal(t, "ClearRecords", next(),
		"the handler got the re-fetched records without being cleared first")
	assert.Equal(t, "UpdateRecords", next())
}
