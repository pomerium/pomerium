package metrics // import "github.com/pomerium/pomerium/internal/metrics"

import (
	"context"
	"strings"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/pomerium/pomerium/internal/log"
	"go.opencensus.io/stats"
	"go.opencensus.io/stats/view"
	"go.opencensus.io/tag"
	"google.golang.org/grpc"
	"google.golang.org/grpc/status"
)

var (
	grpcServerRequestCount    = stats.Int64("grpc_server_requests_total", "Total grpc Requests", "1")
	grpcServerResponseSize    = stats.Int64("grpc_server_response_size_bytes", "grpc Server Response Size in bytes", "bytes")
	grpcServerRequestDuration = stats.Int64("grpc_server_request_duration_ms", "grpc Request duration in ms", "ms")

	grpcClientRequestCount    = stats.Int64("grpc_client_requests_total", "Total grpc Client Requests", "1")
	grpcClientResponseSize    = stats.Int64("grpc_client_response_size_bytes", "grpc Client Response Size in bytes", "bytes")
	grpcClientRequestDuration = stats.Int64("grpc_client_request_duration_ms", "grpc Client Request duration in ms", "ms")

	// GRPCServerRequestCountView is an OpenCensus view which tracks GRPC Server requests by pomerium service, host, grpc service, grpc method, and status
	GRPCServerRequestCountView = &view.View{
		Name:        grpcServerRequestCount.Name(),
		Measure:     grpcServerRequestCount,
		Description: grpcServerRequestCount.Description(),
		TagKeys:     []tag.Key{keyService, keyHost, keyMethod, keyStatus, keyGRPCService},
		Aggregation: view.Count(),
	}

	// GRPCServerRequestDurationView is an OpenCensus view which tracks GRPC Server request duration by pomerium service, host, grpc service, grpc method, and statu
	GRPCServerRequestDurationView = &view.View{
		Name:        grpcServerRequestDuration.Name(),
		Measure:     grpcServerRequestDuration,
		Description: grpcServerRequestDuration.Description(),
		TagKeys:     []tag.Key{keyService, keyHost, keyMethod, keyStatus, keyGRPCService},
		Aggregation: view.Distribution(
			1, 2, 5, 7, 10, 25, 500, 750,
			100, 250, 500, 750,
			1000, 2500, 5000, 7500,
			10000, 25000, 50000, 75000,
			100000,
		),
	}

	// GRPCServerResponseSizeView is an OpenCensus view which tracks GRPC Server request duration by pomerium service, host, grpc service, grpc method, and statu
	GRPCServerResponseSizeView = &view.View{
		Name:        grpcServerResponseSize.Name(),
		Measure:     grpcServerResponseSize,
		Description: grpcServerResponseSize.Description(),
		TagKeys:     []tag.Key{keyService, keyHost, keyMethod, keyStatus, keyGRPCService},
		Aggregation: view.Distribution(
			1, 256, 512, 1024, 2048, 8192, 16384, 32768, 65536, 131072, 262144, 524288,
			1048576, 2097152, 4194304, 8388608,
		),
	}

	// GRPCClientRequestCountView is an OpenCensus view which tracks GRPC Client requests by pomerium service, target host, grpc service, grpc method, and statu
	GRPCClientRequestCountView = &view.View{
		Name:        grpcClientRequestCount.Name(),
		Measure:     grpcClientRequestCount,
		Description: grpcClientRequestCount.Description(),
		TagKeys:     []tag.Key{keyService, keyHost, keyMethod, keyStatus, keyGRPCService},
		Aggregation: view.Count(),
	}

	// GRPCClientRequestDurationView is an OpenCensus view which tracks GRPC Client request duration by pomerium service, target host, grpc service, grpc method, and statu
	GRPCClientRequestDurationView = &view.View{
		Name:        grpcClientRequestDuration.Name(),
		Measure:     grpcClientRequestDuration,
		Description: grpcClientRequestDuration.Description(),
		TagKeys:     []tag.Key{keyService, keyHost, keyMethod, keyStatus, keyGRPCService},
		Aggregation: view.Distribution(
			1, 2, 5, 7, 10, 25, 500, 750,
			100, 250, 500, 750,
			1000, 2500, 5000, 7500,
			10000, 25000, 50000, 75000,
			100000,
		),
	}

	// GRPCClientResponseSizeView  is an OpenCensus view which tracks GRPC Client response size by pomerium service, target host, grpc service, grpc method, and statu
	GRPCClientResponseSizeView = &view.View{
		Name:        grpcClientResponseSize.Name(),
		Measure:     grpcClientResponseSize,
		Description: grpcClientResponseSize.Description(),
		TagKeys:     []tag.Key{keyService, keyHost, keyMethod, keyStatus, keyGRPCService},
		Aggregation: view.Distribution(
			1, 256, 512, 1024, 2048, 8192, 16384, 32768, 65536, 131072, 262144, 524288,
			1048576, 2097152, 4194304, 8388608,
		),
	}
)

// GRPCClientInterceptor creates a UnaryClientInterceptor which tracks metrics of grpc client requests
func GRPCClientInterceptor(service string) grpc.UnaryClientInterceptor {
	return func(
		ctx context.Context,
		method string,
		req interface{},
		reply interface{},
		cc *grpc.ClientConn,
		invoker grpc.UnaryInvoker,
		opts ...grpc.CallOption) error {

		startTime := time.Now()

		// Calls the invoker to execute RPC
		err := invoker(ctx, method, req, reply, cc, opts...)

		// Split the method into parts for better slicing
		rpcInfo := strings.SplitN(method, "/", 3)
		var rpcMethod string
		var rpcService string
		if len(rpcInfo) == 3 {
			rpcService = rpcInfo[1]
			rpcMethod = rpcInfo[2]
		}

		responseStatus, _ := status.FromError(err)
		ctx, tagErr := tag.New(
			context.Background(),
			tag.Insert(keyService, service),
			tag.Insert(keyHost, cc.Target()),
			tag.Insert(keyMethod, rpcMethod),
			tag.Insert(keyGRPCService, rpcService),
			tag.Insert(keyStatus, responseStatus.Code().String()),
		)

		if tagErr != nil {
			log.Warn().Err(tagErr).Str("context", "HTTPMetricsRoundTripper").Msg("Failed to create context tag")
		} else {
			responseProto := reply.(proto.Message)
			responseSize := proto.Size(responseProto)

			stats.Record(ctx,
				grpcClientRequestCount.M(1),
				grpcClientRequestDuration.M(time.Since(startTime).Nanoseconds()/int64(time.Millisecond)),
				grpcClientResponseSize.M(int64(responseSize)),
			)
		}

		return err
	}

}
