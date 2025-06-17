package databroker

import (
	"context"
	"math/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockFF struct {
	clear  chan struct{}
	update chan uint64
}

func (ff *mockFF) ClearRecords(_ context.Context) {
	ff.clear <- struct{}{}
}

func (ff *mockFF) UpdateRecords(_ context.Context, sv uint64, _ []*Record) {
	time.Sleep(time.Millisecond * time.Duration(rand.Intn(5)))
	ff.update <- sv
}

func (ff *mockFF) GetDataBrokerServiceClient() DataBrokerServiceClient {
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
	ctx, cancel := context.WithTimeout(t.Context(), time.Second*15)
	defer cancel()

	m := &mockFF{
		clear:  make(chan struct{}),
		update: make(chan uint64),
	}

	f := newFastForwardHandler(ctx, m)

	for x := 0; x < 100; x++ {
		n := rand.Intn(100) + 1
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
