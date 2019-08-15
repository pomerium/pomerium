package clients // import "github.com/pomerium/pomerium/proxy/clients"

import (
	"context"
	"testing"
	"time"

	"google.golang.org/grpc"
)

func Test_grpcTimeoutInterceptor(t *testing.T) {

	mockInvoker := func(sleepTime time.Duration, wantFail bool) grpc.UnaryInvoker {
		return func(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, opts ...grpc.CallOption) error {
			time.Sleep(sleepTime)
			deadline, ok := ctx.Deadline()
			if !ok {
				t.Fatal("No deadline set")
			}

			if ok && time.Now().After(deadline) && !wantFail {
				t.Error("Deadline exceeded, but should not have")
			} else if time.Now().Before(deadline) && wantFail {
				t.Error("Deadline not exceeded, but should have")
			}
			return nil
		}
	}

	timeOut := 10 * time.Millisecond
	to := grpcTimeoutInterceptor(timeOut)

	to(context.Background(), "test", nil, nil, nil, mockInvoker(timeOut*2, true))
	to(context.Background(), "test", nil, nil, nil, mockInvoker(timeOut/2, false))

}
