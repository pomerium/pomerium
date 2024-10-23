package testutil

import (
	"context"
	"testing"
	"time"
)

// GetContext gets a context for a testing.T.
func GetContext(t *testing.T, maxWait time.Duration) context.Context {
	t.Helper()

	ctx := context.Background()
	ctx, clearTimeout := context.WithTimeout(ctx, maxWait)
	t.Cleanup(clearTimeout)

	if deadline, ok := t.Deadline(); ok {
		var clearDeadline context.CancelFunc
		ctx, clearDeadline = context.WithDeadline(ctx, deadline)
		t.Cleanup(clearDeadline)
	}

	return ctx
}
