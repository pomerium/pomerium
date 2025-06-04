package metrics

import (
	"context"
	"testing"

	"go.opencensus.io/plugin/ocgrpc"
	"go.opencensus.io/stats/view"
	"google.golang.org/grpc"
	"google.golang.org/grpc/stats"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

var statsHandler = &ocgrpc.ServerHandler{}

type testInvoker struct {
	invokeResult error
	statsHandler stats.Handler
}

func (t testInvoker) UnaryInvoke(ctx context.Context, method string, _, reply any, _ *grpc.ClientConn, _ ...grpc.CallOption) error {
	r := reply.(*wrapperspb.StringValue)
	r.Value = "hello"

	ctx = t.statsHandler.TagRPC(ctx, &stats.RPCTagInfo{FullMethodName: method})
	t.statsHandler.HandleRPC(ctx, &stats.InPayload{Client: true, Length: len(r.Value)})
	t.statsHandler.HandleRPC(ctx, &stats.OutPayload{Client: true, Length: len(r.Value)})
	t.statsHandler.HandleRPC(ctx, &stats.End{Client: true, Error: t.invokeResult})

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
		wantgrpcClientRequestSize     string
	}{
		{
			name:                          "ok authorize",
			method:                        "/authorize.Authorizer/Authorize",
			errorCode:                     nil,
			wantgrpcClientResponseSize:    "{ { {grpc_client_status OK}{grpc_method Authorize}{grpc_service authorize.Authorizer}{host dns:localhost:9999}{service test_service} }&{1 5 5 5 0 [0 0 0 1 0 0 0 0 0 0 0 0 0 0 0 0]",
			wantgrpcClientRequestDuration: "{ { {grpc_client_status OK}{grpc_method Authorize}{grpc_service authorize.Authorizer}{host dns:localhost:9999}{service test_service} }",
			wantgrpcClientRequestCount:    "{ { {grpc_client_status OK}{grpc_method Authorize}{grpc_service authorize.Authorizer}{host dns:localhost:9999}{service test_service} }",
			wantgrpcClientRequestSize:     "{ { {grpc_client_status OK}{grpc_method Authorize}{grpc_service authorize.Authorizer}{host dns:localhost:9999}{service test_service} }&{1 5 5 5 0 [0 0 0 1 0 0 0 0 0 0 0 0 0 0 0 0]",
		},
		{
			name:                          "unknown validate",
			method:                        "/authenticate.Authenticator/Validate",
			errorCode:                     status.Error(14, ""),
			wantgrpcClientResponseSize:    "{ { {grpc_client_status UNAVAILABLE}{grpc_method Validate}{grpc_service authenticate.Authenticator}{host dns:localhost:9999}{service test_service} }&{1 5 5 5 0 [0 0 0 1 0 0 0 0 0 0 0 0 0 0 0 0]",
			wantgrpcClientRequestDuration: "{ { {grpc_client_status UNAVAILABLE}{grpc_method Validate}{grpc_service authenticate.Authenticator}{host dns:localhost:9999}{service test_service} }",
			wantgrpcClientRequestCount:    "{ { {grpc_client_status UNAVAILABLE}{grpc_method Validate}{grpc_service authenticate.Authenticator}{host dns:localhost:9999}{service test_service} }",
			wantgrpcClientRequestSize:     "{ { {grpc_client_status UNAVAILABLE}{grpc_method Validate}{grpc_service authenticate.Authenticator}{host dns:localhost:9999}{service test_service} }&{1 5 5 5 0 [0 0 0 1 0 0 0 0 0 0 0 0 0 0 0 0]",
		},
		{
			name:                          "broken method parsing",
			method:                        "f",
			errorCode:                     status.Error(14, ""),
			wantgrpcClientResponseSize:    "{ { {grpc_client_status UNAVAILABLE}{host dns:localhost:9999}{service test_service} }&{1 5 5 5 0 [0 0 0 1 0 0 0 0 0 0 0 0 0 0 0 0]",
			wantgrpcClientRequestDuration: "{ { {grpc_client_status UNAVAILABLE}{host dns:localhost:9999}{service test_service} }",
			wantgrpcClientRequestCount:    "{ { {grpc_client_status UNAVAILABLE}{host dns:localhost:9999}{service test_service} }",
			wantgrpcClientRequestSize:     "{ { {grpc_client_status UNAVAILABLE}{host dns:localhost:9999}{service test_service} }&{1 5 5 5 0 [0 0 0 1 0 0 0 0 0 0 0 0 0 0 0 0]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			view.Unregister(GRPCClientViews...)
			view.Register(GRPCClientViews...)

			invoker := testInvoker{
				invokeResult: tt.errorCode,
				statsHandler: &ocgrpc.ClientHandler{},
			}
			var reply wrapperspb.StringValue

			interceptor(t.Context(), tt.method, nil, &reply, newTestCC(t), invoker.UnaryInvoke)

			testDataRetrieval(GRPCClientResponseSizeView, t, tt.wantgrpcClientResponseSize)
			testDataRetrieval(GRPCClientRequestDurationView, t, tt.wantgrpcClientRequestDuration)
			testDataRetrieval(GRPCClientRequestCountView, t, tt.wantgrpcClientRequestCount)
			testDataRetrieval(GRPCClientRequestSizeView, t, tt.wantgrpcClientRequestSize)
		})
	}
}

func mockServerRPCHandle(metricsHandler *GRPCServerMetricsHandler, method string, errorCode error) {
	message := "hello"
	ctx := statsHandler.TagRPC(context.Background(), &stats.RPCTagInfo{FullMethodName: method})
	ctx = metricsHandler.TagRPC(ctx, &stats.RPCTagInfo{FullMethodName: method})

	statsHandler.HandleRPC(ctx, &stats.InPayload{Client: false, Length: len(message)})
	statsHandler.HandleRPC(ctx, &stats.OutPayload{Client: false, Length: len(message)})
	statsHandler.HandleRPC(ctx, &stats.End{Client: false, Error: errorCode})
}

func Test_GRPCServerMetricsHandler(t *testing.T) {
	tests := []struct {
		name                          string
		method                        string
		errorCode                     error
		wantgrpcServerResponseSize    string
		wantgrpcServerRequestDuration string
		wantgrpcServerRequestCount    string
		wantgrpcServerRequestSizeView string
	}{
		{
			name:                          "ok authorize",
			method:                        "/authorize.Authorizer/Authorize",
			errorCode:                     nil,
			wantgrpcServerResponseSize:    "{ { {grpc_method Authorize}{grpc_server_status OK}{grpc_service authorize.Authorizer}{service test_service} }&{1 5 5 5 0 [0 0 0 1 0 0 0 0 0 0 0 0 0 0 0 0]",
			wantgrpcServerRequestDuration: "{ { {grpc_method Authorize}{grpc_server_status OK}{grpc_service authorize.Authorizer}{service test_service} }",
			wantgrpcServerRequestCount:    "{ { {grpc_method Authorize}{grpc_server_status OK}{grpc_service authorize.Authorizer}{service test_service} }",
			wantgrpcServerRequestSizeView: "{ { {grpc_method Authorize}{grpc_server_status OK}{grpc_service authorize.Authorizer}{service test_service} }&{1 5 5 5 0 [0 0 0 1 0 0 0 0 0 0 0 0 0 0 0 0]",
		},
		{
			name:                          "unknown validate",
			method:                        "/authenticate.Authenticator/Validate",
			errorCode:                     status.Error(14, ""),
			wantgrpcServerResponseSize:    "{ { {grpc_method Validate}{grpc_server_status UNAVAILABLE}{grpc_service authenticate.Authenticator}{service test_service} }&{1 5 5 5 0 [0 0 0 1 0 0 0 0 0 0 0 0 0 0 0 0]",
			wantgrpcServerRequestDuration: "{ { {grpc_method Validate}{grpc_server_status UNAVAILABLE}{grpc_service authenticate.Authenticator}{service test_service} }",
			wantgrpcServerRequestCount:    "{ { {grpc_method Validate}{grpc_server_status UNAVAILABLE}{grpc_service authenticate.Authenticator}{service test_service} }",
			wantgrpcServerRequestSizeView: "{ { {grpc_method Validate}{grpc_server_status UNAVAILABLE}{grpc_service authenticate.Authenticator}{service test_service} }&{1 5 5 5 0 [0 0 0 1 0 0 0 0 0 0 0 0 0 0 0 0]",
		},
		{
			name:                          "broken method parsing",
			method:                        "f",
			errorCode:                     status.Error(14, ""),
			wantgrpcServerResponseSize:    "{ { {grpc_server_status UNAVAILABLE}{service test_service} }&{1 5 5 5 0 [0 0 0 1 0 0 0 0 0 0 0 0 0 0 0 0]",
			wantgrpcServerRequestDuration: "{ { {grpc_server_status UNAVAILABLE}{service test_service} }",
			wantgrpcServerRequestCount:    "{ { {grpc_server_status UNAVAILABLE}{service test_service} }",
			wantgrpcServerRequestSizeView: "{ { {grpc_server_status UNAVAILABLE}{service test_service} }&{1 5 5 5 0 [0 0 0 1 0 0 0 0 0 0 0 0 0 0 0 0]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			view.Unregister(GRPCServerViews...)
			view.Register(GRPCServerViews...)

			metricsHandler := NewGRPCServerMetricsHandler("test_service")
			mockServerRPCHandle(metricsHandler, tt.method, tt.errorCode)

			testDataRetrieval(GRPCServerResponseSizeView, t, tt.wantgrpcServerResponseSize)
			testDataRetrieval(GRPCServerRequestDurationView, t, tt.wantgrpcServerRequestDuration)
			testDataRetrieval(GRPCServerRequestCountView, t, tt.wantgrpcServerRequestCount)
			testDataRetrieval(GRPCServerRequestSizeView, t, tt.wantgrpcServerRequestSizeView)
		})
	}
}
