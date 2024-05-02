package grpc

import (
	"context"
	"testing"
	"time"

	"google.golang.org/grpc"
)

func Test_grpcTimeoutInterceptor(t *testing.T) {
	mockInvoker := func(sleepTime time.Duration, wantFail bool) grpc.UnaryInvoker {
		return func(ctx context.Context, _ string, _, _ any, _ *grpc.ClientConn, _ ...grpc.CallOption) error {
			time.Sleep(sleepTime)
			deadline, ok := ctx.Deadline()
			if !ok {
				t.Fatal("No deadline set")
			}

			now := time.Now()

			if ok && now.After(deadline) && !wantFail {
				t.Errorf("Deadline exceeded, but should not have.  now=%v, deadline=%v", now, deadline)
			} else if now.Before(deadline) && wantFail {
				t.Errorf("Deadline not exceeded, but should have.  now=%v, deadline=%v", now, deadline)
			}
			return nil
		}
	}

	timeOut := 300 * time.Millisecond
	to := grpcTimeoutInterceptor(timeOut)

	to(context.Background(), "test", nil, nil, nil, mockInvoker(timeOut*2, true))
	to(context.Background(), "test", nil, nil, nil, mockInvoker(timeOut/2, false))
}
