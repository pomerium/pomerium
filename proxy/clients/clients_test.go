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
			select {
			case <-ctx.Done():
				if !wantFail {
					t.Error("Deadline should not have been exceeded")
				}
				return nil
			default:
				if wantFail {
					t.Error("Deadline not exceeded but should have been")
				}
			}
			return nil
		}
	}

	timeOut := 5 * time.Millisecond
	to := grpcTimeoutInterceptor(timeOut)

	to(context.Background(), "test", nil, nil, nil, mockInvoker(timeOut*2, true))
	to(context.Background(), "test", nil, nil, nil, mockInvoker(timeOut/2, false))

}
