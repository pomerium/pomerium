package telemetry // import "github.com/pomerium/pomerium/internal/telemetry"

import (
	"context"
	"strings"

	"github.com/pomerium/pomerium/internal/log"
	"go.opencensus.io/plugin/ocgrpc"
	"go.opencensus.io/stats/view"
	"go.opencensus.io/tag"
	"google.golang.org/grpc"
	grpcstats "google.golang.org/grpc/stats"
)

var (
	grpcSizeDistribution = view.Distribution(
		1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024,
		2048, 4096, 8192, 16384,
	)
	grcpLatencyDistribution = view.Distribution(
		1, 2, 5, 7, 10, 25, 50, 75,
		100, 250, 500, 750, 1000,
	)

	// GRPCServerRequestCountView is an OpenCensus view which counts GRPC Server
	// requests by pomerium service, grpc service, grpc method, and status
	GRPCServerRequestCountView = &view.View{
		Name:        "grpc_server_requests_total",
		Measure:     ocgrpc.ServerLatency,
		Description: "Total grpc Requests",
		TagKeys:     []tag.Key{keyService, keyGRPCMethod, ocgrpc.KeyServerStatus, keyGRPCService},
		Aggregation: view.Count(),
	}

	// GRPCServerRequestDurationView is an OpenCensus view which tracks GRPC Server
	// request duration by pomerium service, grpc service, grpc method, and status
	GRPCServerRequestDurationView = &view.View{
		Name:        "grpc_server_request_duration_ms",
		Measure:     ocgrpc.ServerLatency,
		Description: "grpc Request duration in ms",
		TagKeys:     []tag.Key{keyService, keyGRPCMethod, ocgrpc.KeyServerStatus, keyGRPCService},
		Aggregation: grcpLatencyDistribution,
	}

	// GRPCServerResponseSizeView is an OpenCensus view which tracks GRPC Server
	// response size by pomerium service, grpc service, grpc method, and status
	GRPCServerResponseSizeView = &view.View{
		Name:        "grpc_server_response_size_bytes",
		Measure:     ocgrpc.ServerSentBytesPerRPC,
		Description: "grpc Server Response Size in bytes",
		TagKeys:     []tag.Key{keyService, keyGRPCMethod, ocgrpc.KeyServerStatus, keyGRPCService},
		Aggregation: grpcSizeDistribution,
	}

	// GRPCServerRequestSizeView is an OpenCensus view which tracks GRPC Server
	// request size by pomerium service, grpc service, grpc method, and status
	GRPCServerRequestSizeView = &view.View{
		Name:        "grpc_server_request_size_bytes",
		Measure:     ocgrpc.ServerReceivedBytesPerRPC,
		Description: "grpc Server Request Size in bytes",
		TagKeys:     []tag.Key{keyService, keyGRPCMethod, ocgrpc.KeyServerStatus, keyGRPCService},
		Aggregation: grpcSizeDistribution,
	}

	// GRPCClientRequestCountView is an OpenCensus view which tracks GRPC Client
	// requests by pomerium service, target host, grpc service, grpc method, and status
	GRPCClientRequestCountView = &view.View{
		Name:        "grpc_client_requests_total",
		Measure:     ocgrpc.ClientRoundtripLatency,
		Description: "Total grpc Client Requests",
		TagKeys:     []tag.Key{keyService, keyHost, keyGRPCMethod, keyGRPCService, ocgrpc.KeyClientStatus},
		Aggregation: view.Count(),
	}

	// GRPCClientRequestDurationView is an OpenCensus view which tracks GRPC Client
	// request duration by pomerium service, target host, grpc service, grpc method, and status
	GRPCClientRequestDurationView = &view.View{
		Name:        "grpc_client_request_duration_ms",
		Measure:     ocgrpc.ClientRoundtripLatency,
		Description: "grpc Client Request duration in ms",
		TagKeys:     []tag.Key{keyService, keyHost, keyGRPCMethod, keyGRPCService, ocgrpc.KeyClientStatus},
		Aggregation: grcpLatencyDistribution,
	}

	// GRPCClientResponseSizeView  is an OpenCensus view which tracks GRPC Client
	// response size by pomerium service, target host, grpc service, grpc method, and status
	GRPCClientResponseSizeView = &view.View{
		Name:        "grpc_client_response_size_bytes",
		Measure:     ocgrpc.ClientReceivedBytesPerRPC,
		Description: "grpc Client Response Size in bytes",
		TagKeys:     []tag.Key{keyService, keyHost, keyGRPCMethod, keyGRPCService, ocgrpc.KeyClientStatus},
		Aggregation: grpcSizeDistribution,
	}

	// GRPCClientRequestSizeView  is an OpenCensus view which tracks GRPC Client
	// request size by pomerium service, target host, grpc service, grpc method, and status
	GRPCClientRequestSizeView = &view.View{
		Name:        "grpc_client_request_size_bytes",
		Measure:     ocgrpc.ClientSentBytesPerRPC,
		Description: "grpc Client Request Size in bytes",
		TagKeys:     []tag.Key{keyService, keyHost, keyGRPCMethod, keyGRPCService, ocgrpc.KeyClientStatus},
		Aggregation: grpcSizeDistribution,
	}
)

// GRPCClientInterceptor creates a UnaryClientInterceptor which updates the RPC
// context with metric tag metadata
func GRPCClientInterceptor(service string) grpc.UnaryClientInterceptor {
	return func(
		ctx context.Context,
		method string,
		req interface{},
		reply interface{},
		cc *grpc.ClientConn,
		invoker grpc.UnaryInvoker,
		opts ...grpc.CallOption) error {

		// Split the method into parts for better slicing
		rpcInfo := strings.SplitN(method, "/", 3)
		var rpcMethod string
		var rpcService string
		if len(rpcInfo) == 3 {
			rpcService = rpcInfo[1]
			rpcMethod = rpcInfo[2]
		}

		taggedCtx, tagErr := tag.New(
			ctx,
			tag.Insert(keyService, service),
			tag.Insert(keyHost, cc.Target()),
			tag.Insert(keyGRPCMethod, rpcMethod),
			tag.Insert(keyGRPCService, rpcService),
		)
		if tagErr != nil {
			log.Warn().Err(tagErr).Str("context", "GRPCClientInterceptor").Msg("internal/telemetry: Failed to create context")
			return invoker(ctx, method, req, reply, cc, opts...)
		}

		// Calls the invoker to execute RPC
		return invoker(taggedCtx, method, req, reply, cc, opts...)
	}

}

// GRPCServerStatsHandler provides a grpc stats.Handler for a pomerium service to add tags and track
// metrics to server side calls
type GRPCServerStatsHandler struct {
	service string
	grpcstats.Handler
}

// TagRPC implements grpc.stats.Handler and adds tags to the context of a given RPC
func (h *GRPCServerStatsHandler) TagRPC(ctx context.Context, tagInfo *grpcstats.RPCTagInfo) context.Context {

	handledCtx := h.Handler.TagRPC(ctx, tagInfo)

	// Split the method into parts for better slicing
	rpcInfo := strings.SplitN(tagInfo.FullMethodName, "/", 3)
	var rpcMethod string
	var rpcService string
	if len(rpcInfo) == 3 {
		rpcService = rpcInfo[1]
		rpcMethod = rpcInfo[2]
	}

	taggedCtx, tagErr := tag.New(
		handledCtx,
		tag.Insert(keyService, h.service),
		tag.Insert(keyGRPCMethod, rpcMethod),
		tag.Insert(keyGRPCService, rpcService),
	)
	if tagErr != nil {
		log.Warn().Err(tagErr).Str("context", "GRPCServerStatsHandler").Msg("internal/telemetry: Failed to create context")
		return handledCtx

	}

	return taggedCtx
}

// NewGRPCServerStatsHandler creates a new GRPCServerStatsHandler for a pomerium service
func NewGRPCServerStatsHandler(service string) grpcstats.Handler {
	return &GRPCServerStatsHandler{service: service, Handler: &ocgrpc.ServerHandler{}}
}
