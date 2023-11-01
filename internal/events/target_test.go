package events_test

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/pomerium/pomerium/internal/events"
)

func TestTarget(t *testing.T) {
	t.Parallel()

	var target events.Target[int64]
	defer target.Close()

	var calls1, calls2, calls3 atomic.Int64
	h1 := target.AddListener(func(i int64) {
		calls1.Add(i)
	})
	h2 := target.AddListener(func(i int64) {
		calls2.Add(i)
	})
	h3 := target.AddListener(func(i int64) {
		calls3.Add(i)
	})

	shouldBe := func(i1, i2, i3 int64) {
		t.Helper()

		assert.Eventually(t, func() bool { return calls1.Load() == i1 }, time.Millisecond*10, time.Microsecond*100)
		assert.Eventually(t, func() bool { return calls2.Load() == i2 }, time.Millisecond*10, time.Microsecond*100)
		assert.Eventually(t, func() bool { return calls3.Load() == i3 }, time.Millisecond*10, time.Microsecond*100)
	}

	target.Dispatch(1)
	shouldBe(1, 1, 1)

	target.RemoveListener(h2)
	target.Dispatch(2)
	shouldBe(3, 1, 3)

	target.RemoveListener(h1)
	target.Dispatch(3)
	shouldBe(3, 1, 6)

	target.RemoveListener(h3)
	target.Dispatch(4)
	shouldBe(3, 1, 6)
}
