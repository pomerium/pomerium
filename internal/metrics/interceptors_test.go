package metrics

import (
	"context"
	"testing"

	"go.opencensus.io/stats/view"
	"google.golang.org/grpc"
	"google.golang.org/grpc/status"
)

type testProto struct {
	message string
}

func (t testProto) Reset()        {}
func (t testProto) ProtoMessage() {}
func (t testProto) String() string {
	return t.message
}

func (t testProto) XXX_Size() int {
	return len([]byte(t.message))
}

func (t testProto) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return []byte(t.message), nil
}

type testInvoker struct {
	invokeResult error
}

func (t testInvoker) UnaryInvoke(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, opts ...grpc.CallOption) error {
	r := reply.(*testProto)
	r.message = "hello"
	return t.invokeResult
}

func newTestCC(t *testing.T) *grpc.ClientConn {
	testCC, err := grpc.Dial("dns:localhost:9999", grpc.WithInsecure())
	if err != nil {
		t.Fatalf("Failed to create testCC: %s", err)
	}
	return testCC
}
func Test_GRPCClientInterceptor(t *testing.T) {

	interceptor := GRPCClientInterceptor("test_service")

	tests := []struct {
		name                          string
		method                        string
		errorCode                     error
		wantgrpcClientResponseSize    string
		wantgrpcClientRequestDuration string
		wantgrpcClientRequestCount    string
	}{
		{
			name:                          "ok authorize",
			method:                        "/authorize.Authorizer/Authorize",
			errorCode:                     nil,
			wantgrpcClientResponseSize:    "{ { {grpc_service authorize.Authorizer}{host dns:localhost:9999}{method Authorize}{service test_service}{status OK} }&{1 5 5 5 0 [0 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]",
			wantgrpcClientRequestDuration: "{ { {grpc_service authorize.Authorizer}{host dns:localhost:9999}{method Authorize}{service test_service}{status OK} }&{1",
			wantgrpcClientRequestCount:    "{ { {grpc_service authorize.Authorizer}{host dns:localhost:9999}{method Authorize}{service test_service}{status OK} }&{1",
		},
		{
			name:                          "unknown validate",
			method:                        "/authenticate.Authenticator/Validate",
			errorCode:                     status.Error(14, ""),
			wantgrpcClientResponseSize:    "{ { {grpc_service authenticate.Authenticator}{host dns:localhost:9999}{method Validate}{service test_service}{status Unavailable} }&{1 5 5 5 0 [0 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]",
			wantgrpcClientRequestDuration: "{ { {grpc_service authenticate.Authenticator}{host dns:localhost:9999}{method Validate}{service test_service}{status Unavailable} }&{1",
			wantgrpcClientRequestCount:    "{ { {grpc_service authenticate.Authenticator}{host dns:localhost:9999}{method Validate}{service test_service}{status Unavailable} }&{1",
		},
		{
			name:                          "broken method parsing",
			method:                        "f",
			errorCode:                     status.Error(14, ""),
			wantgrpcClientResponseSize:    "{ { {host dns:localhost:9999}{service test_service}{status Unavailable} }&{1 5 5 5 0 [0 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]",
			wantgrpcClientRequestDuration: "{ { {host dns:localhost:9999}{service test_service}{status Unavailable} }&{1",
			wantgrpcClientRequestCount:    "{ { {host dns:localhost:9999}{service test_service}{status Unavailable} }&{1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			view.Unregister(GRPCClientRequestCountView, GRPCClientRequestDurationView, GRPCClientResponseSizeView)
			view.Register(GRPCClientRequestCountView, GRPCClientRequestDurationView, GRPCClientResponseSizeView)

			invoker := testInvoker{
				invokeResult: tt.errorCode,
			}
			var reply testProto

			interceptor(context.Background(), tt.method, nil, &reply, newTestCC(t), invoker.UnaryInvoke)

			testDataRetrieval(grpcClientResponseSize, t, tt.wantgrpcClientResponseSize)
			testDataRetrieval(grpcClientRequestDuration, t, tt.wantgrpcClientRequestDuration)
			testDataRetrieval(grpcClientRequestCount, t, tt.wantgrpcClientRequestCount)
		})
	}
}
