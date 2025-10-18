package events

import (
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/testing/protocmp"
)

func TestManager(t *testing.T) {
	t.Parallel()

	mgr := New()

	received := make(chan Event, 1)
	handle := mgr.Register(func(evt Event) {
		received <- evt
	})
	assert.NotEmpty(t, handle)

	expect := &LastError{Message: "TEST"}
	mgr.Dispatch(expect)

	assert.Eventually(t, func() bool {
		select {
		case evt := <-received:
			return cmp.Equal(evt, expect, protocmp.Transform())
		default:
			return false
		}
	}, time.Second, time.Millisecond*20)
}
