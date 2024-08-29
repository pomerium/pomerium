package metrics

import (
	"context"
	"strings"

	"go.opencensus.io/plugin/ocgrpc"
	"go.opencensus.io/stats/view"
	"go.opencensus.io/tag"
	"google.golang.org/grpc"
	grpcstats "google.golang.org/grpc/stats"

	"github.com/pomerium/pomerium/internal/log"
)

// GRPC Views
var (
	// GRPCClientViews contains opencensus views for GRPC Client metrics.
	GRPCClientViews = []*view.View{
		GRPCClientRequestCountView,
		GRPCClientRequestDurationView,
		GRPCClientResponseSizeView,
		GRPCClientRequestSizeView,
	}
	// GRPCServerViews contains opencensus views for GRPC Server metrics.
	GRPCServerViews = []*view.View{
		GRPCServerRequestCountView,
		GRPCServerRequestDurationView,
		GRPCServerResponseSizeView,
		GRPCServerRequestSizeView,
	}

	// GRPCServerRequestCountView is an OpenCensus view which counts GRPC Server
	// requests by pomerium service, grpc service, grpc method, and status
	GRPCServerRequestCountView = &view.View{
		Name:        "grpc/server/requests_total",
		Measure:     ocgrpc.ServerLatency,
		Description: "Total grpc Requests",
		TagKeys:     []tag.Key{TagKeyService, TagKeyGRPCMethod, ocgrpc.KeyServerStatus, TagKeyGRPCService},
		Aggregation: view.Count(),
	}

	// GRPCServerRequestDurationView is an OpenCensus view which tracks GRPC Server
	// request duration by pomerium service, grpc service, grpc method, and status
	GRPCServerRequestDurationView = &view.View{
		Name:        "grpc/server/request_duration_ms",
		Measure:     ocgrpc.ServerLatency,
		Description: "grpc Request duration in ms",
		TagKeys:     []tag.Key{TagKeyService, TagKeyGRPCMethod, ocgrpc.KeyServerStatus, TagKeyGRPCService},
		Aggregation: DefaultMillisecondsDistribution,
	}

	// GRPCServerResponseSizeView is an OpenCensus view which tracks GRPC Server
	// response size by pomerium service, grpc service, grpc method, and status
	GRPCServerResponseSizeView = &view.View{
		Name:        "grpc/server/response_size_bytes",
		Measure:     ocgrpc.ServerSentBytesPerRPC,
		Description: "grpc Server Response Size in bytes",
		TagKeys:     []tag.Key{TagKeyService, TagKeyGRPCMethod, ocgrpc.KeyServerStatus, TagKeyGRPCService},
		Aggregation: grpcSizeDistribution,
	}

	// GRPCServerRequestSizeView is an OpenCensus view which tracks GRPC Server
	// request size by pomerium service, grpc service, grpc method, and status
	GRPCServerRequestSizeView = &view.View{
		Name:        "grpc/server/request_size_bytes",
		Measure:     ocgrpc.ServerReceivedBytesPerRPC,
		Description: "grpc Server Request Size in bytes",
		TagKeys:     []tag.Key{TagKeyService, TagKeyGRPCMethod, ocgrpc.KeyServerStatus, TagKeyGRPCService},
		Aggregation: grpcSizeDistribution,
	}

	// GRPCClientRequestCountView is an OpenCensus view which tracks GRPC Client
	// requests by pomerium service, target host, grpc service, grpc method, and status
	GRPCClientRequestCountView = &view.View{
		Name:        "grpc/client/requests_total",
		Measure:     ocgrpc.ClientRoundtripLatency,
		Description: "Total grpc Client Requests",
		TagKeys:     []tag.Key{TagKeyService, TagKeyHost, TagKeyGRPCMethod, TagKeyGRPCService, ocgrpc.KeyClientStatus},
		Aggregation: view.Count(),
	}

	// GRPCClientRequestDurationView is an OpenCensus view which tracks GRPC Client
	// request duration by pomerium service, target host, grpc service, grpc method, and status
	GRPCClientRequestDurationView = &view.View{
		Name:        "grpc/client/request_duration_ms",
		Measure:     ocgrpc.ClientRoundtripLatency,
		Description: "grpc Client Request duration in ms",
		TagKeys:     []tag.Key{TagKeyService, TagKeyHost, TagKeyGRPCMethod, TagKeyGRPCService, ocgrpc.KeyClientStatus},
		Aggregation: DefaultMillisecondsDistribution,
	}

	// GRPCClientResponseSizeView  is an OpenCensus view which tracks GRPC Client
	// response size by pomerium service, target host, grpc service, grpc method, and status
	GRPCClientResponseSizeView = &view.View{
		Name:        "grpc/client/response_size_bytes",
		Measure:     ocgrpc.ClientReceivedBytesPerRPC,
		Description: "grpc Client Response Size in bytes",
		TagKeys:     []tag.Key{TagKeyService, TagKeyHost, TagKeyGRPCMethod, TagKeyGRPCService, ocgrpc.KeyClientStatus},
		Aggregation: grpcSizeDistribution,
	}

	// GRPCClientRequestSizeView  is an OpenCensus view which tracks GRPC Client
	// request size by pomerium service, target host, grpc service, grpc method, and status
	GRPCClientRequestSizeView = &view.View{
		Name:        "grpc/client/request_size_bytes",
		Measure:     ocgrpc.ClientSentBytesPerRPC,
		Description: "grpc Client Request Size in bytes",
		TagKeys:     []tag.Key{TagKeyService, TagKeyHost, TagKeyGRPCMethod, TagKeyGRPCService, ocgrpc.KeyClientStatus},
		Aggregation: grpcSizeDistribution,
	}
)

// GRPCClientInterceptor creates a UnaryClientInterceptor which updates the RPC
// context with metric tag metadata
//
// TODO: This handler will NOT currently propagate B3 headers to upstream servers.  See
// GRPCServerStatsHandler for changes required
func GRPCClientInterceptor(service string) grpc.UnaryClientInterceptor {
	return func(
		ctx context.Context,
		method string,
		req any,
		reply any,
		cc *grpc.ClientConn,
		invoker grpc.UnaryInvoker,
		opts ...grpc.CallOption,
	) error {
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
			tag.Upsert(TagKeyService, service),
			tag.Upsert(TagKeyHost, cc.Target()),
			tag.Upsert(TagKeyGRPCMethod, rpcMethod),
			tag.Upsert(TagKeyGRPCService, rpcService),
		)
		if tagErr != nil {
			log.Ctx(ctx).Error().Err(tagErr).Str("context", "GRPCClientInterceptor").Msg("telemetry/metrics: failed to create context")
			return invoker(ctx, method, req, reply, cc, opts...)
		}

		// Calls the invoker to execute RPC
		return invoker(taggedCtx, method, req, reply, cc, opts...)
	}
}

// GRPCServerMetricsHandler implements a telemetry tagRPCHandler methods for metrics
type GRPCServerMetricsHandler struct {
	service string
}

// NewGRPCServerMetricsHandler creates a new GRPCServerStatsHandler for a pomerium service
func NewGRPCServerMetricsHandler(service string) *GRPCServerMetricsHandler {
	return &GRPCServerMetricsHandler{
		service: service,
	}
}

// TagRPC handles adding any metrics related values to the incoming context
func (h *GRPCServerMetricsHandler) TagRPC(ctx context.Context, tagInfo *grpcstats.RPCTagInfo) context.Context {
	// Split the method into parts for better slicing
	rpcInfo := strings.SplitN(tagInfo.FullMethodName, "/", 3)
	var rpcMethod string
	var rpcService string
	if len(rpcInfo) == 3 {
		rpcService = rpcInfo[1]
		rpcMethod = rpcInfo[2]
	}

	taggedCtx, tagErr := tag.New(
		ctx,
		tag.Upsert(TagKeyService, h.service),
		tag.Upsert(TagKeyGRPCMethod, rpcMethod),
		tag.Upsert(TagKeyGRPCService, rpcService),
	)
	if tagErr != nil {
		log.Ctx(ctx).Error().Err(tagErr).Str("context", "GRPCServerStatsHandler").Msg("telemetry/metrics: failed to create context")
		return ctx

	}

	return taggedCtx
}
