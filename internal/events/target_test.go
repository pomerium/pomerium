package events_test

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/pomerium/pomerium/internal/events"
)

func TestTarget(t *testing.T) {
	t.Parallel()

	var target events.Target[int64]
	t.Cleanup(target.Close)

	var calls1, calls2, calls3 atomic.Int64
	h1 := target.AddListener(func(_ context.Context, i int64) {
		calls1.Add(i)
	})
	h2 := target.AddListener(func(_ context.Context, i int64) {
		calls2.Add(i)
	})
	h3 := target.AddListener(func(_ context.Context, i int64) {
		calls3.Add(i)
	})

	shouldBe := func(i1, i2, i3 int64) {
		t.Helper()

		assert.Eventually(t, func() bool { return calls1.Load() == i1 }, time.Second, time.Millisecond)
		assert.Eventually(t, func() bool { return calls2.Load() == i2 }, time.Second, time.Millisecond)
		assert.Eventually(t, func() bool { return calls3.Load() == i3 }, time.Second, time.Millisecond)
	}

	target.Dispatch(context.Background(), 1)
	shouldBe(1, 1, 1)

	target.RemoveListener(h2)
	target.Dispatch(context.Background(), 2)
	shouldBe(3, 1, 3)

	target.RemoveListener(h1)
	target.Dispatch(context.Background(), 3)
	shouldBe(3, 1, 6)

	target.RemoveListener(h3)
	target.Dispatch(context.Background(), 4)
	shouldBe(3, 1, 6)
}

func TestDispatchOrder(t *testing.T) {
	var target events.Target[int64]
	t.Cleanup(target.Close)

	ch := make(chan error)

	var next atomic.Int64

	update := func(_ context.Context, i int64) {
		if n := next.Load(); i != n {
			ch <- fmt.Errorf("want %d, got %d", n, i)
		}
		next.Store(i + 1)
	}

	go func() {
		for i := int64(0); i < 1000; i++ {
			h := target.AddListener(update)
			target.Dispatch(context.Background(), i)
			target.RemoveListener(h)
		}
		ch <- nil
	}()

	if err := <-ch; err != nil {
		t.Fatal(err)
	}
}
