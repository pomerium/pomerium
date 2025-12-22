package ratelimit

import (
	"context"

	envoy_service_ratelimit_v3 "github.com/envoyproxy/go-control-plane/envoy/service/ratelimit/v3"
	oteltrace "go.opentelemetry.io/otel/trace"

	"github.com/pomerium/pomerium/pkg/telemetry/trace"
)

const (
	// DomainSSHInbound is the domain corresponding to incoming requests before they are authenticated
	// and must go through the bespoke oauth code flow
	DomainSSHInbound = "ssh-inbound"
)

var _ envoy_service_ratelimit_v3.RateLimitServiceServer = (*RateLimiter)(nil)

type RateLimiter struct {
	envoy_service_ratelimit_v3.UnsafeRateLimitServiceServer

	underlyingSrv envoy_service_ratelimit_v3.RateLimitServiceServer
	tracer        oteltrace.Tracer
}

func NewRateLimiter(
	traceProvider oteltrace.TracerProvider,
	impl envoy_service_ratelimit_v3.RateLimitServiceServer,
) *RateLimiter {
	return &RateLimiter{
		tracer:        traceProvider.Tracer(trace.PomeriumCoreTracer),
		underlyingSrv: impl,
	}
}

func (r *RateLimiter) ShouldRateLimit(
	ctx context.Context,
	req *envoy_service_ratelimit_v3.RateLimitRequest,
) (*envoy_service_ratelimit_v3.RateLimitResponse, error) {
	ctx, span := r.tracer.Start(ctx, "rls.grpc.ShouldRateLimit")
	defer span.End()
	if r.underlyingSrv != nil {
		return r.underlyingSrv.ShouldRateLimit(ctx, req)
	}

	return &envoy_service_ratelimit_v3.RateLimitResponse{
		OverallCode: envoy_service_ratelimit_v3.RateLimitResponse_OK,
		Statuses:    MakeResponse(envoy_service_ratelimit_v3.RateLimitResponse_OK, len(req.Descriptors)),
	}, nil
}

func MakeResponse(code envoy_service_ratelimit_v3.RateLimitResponse_Code, n int) []*envoy_service_ratelimit_v3.RateLimitResponse_DescriptorStatus {
	ret := make([]*envoy_service_ratelimit_v3.RateLimitResponse_DescriptorStatus, n)

	for i := range n {
		ret[i] = &envoy_service_ratelimit_v3.RateLimitResponse_DescriptorStatus{
			Code: code,
		}
	}
	return ret
}
