package ratelimit

import (
	"context"
	"log/slog"
	"maps"
	"strings"

	envoy_service_ratelimit_v3 "github.com/envoyproxy/go-control-plane/envoy/service/ratelimit/v3"
	oteltrace "go.opentelemetry.io/otel/trace"

	"github.com/pomerium/pomerium/pkg/iterutil"
	"github.com/pomerium/pomerium/pkg/telemetry/trace"
)

const (
	// DomainSSHInbound is the domain corresponding to incoming requests before they are authenticated
	// and must go through the bespoke oauth code flow
	DomainSSHInbound = "ssh-inbound"
	// DomainSSHInFlight is the domain corresponding to requests made during active ssh connections
	DomainSSHInFlight = "ssh-inflight"
)

var _ envoy_service_ratelimit_v3.RateLimitServiceServer = (*RateLimiter)(nil)

type RateLimiter struct {
	envoy_service_ratelimit_v3.UnsafeRateLimitServiceServer
	debug bool

	underlyingSrv envoy_service_ratelimit_v3.RateLimitServiceServer
	tracer        oteltrace.Tracer
}

func NewRateLimiter(
	traceProvider oteltrace.TracerProvider,
	impl envoy_service_ratelimit_v3.RateLimitServiceServer,
) *RateLimiter {
	return &RateLimiter{
		tracer:        traceProvider.Tracer(trace.PomeriumCoreTracer),
		debug:         true,
		underlyingSrv: impl,
	}
}

func (r *RateLimiter) ShouldRateLimit(
	ctx context.Context,
	req *envoy_service_ratelimit_v3.RateLimitRequest,
) (*envoy_service_ratelimit_v3.RateLimitResponse, error) {
	ctx, span := r.tracer.Start(ctx, "rls.grpc.ShouldRateLimit")
	defer span.End()
	if r.debug {
		r.debugLog(req)
	}
	if r.underlyingSrv != nil {
		return r.underlyingSrv.ShouldRateLimit(ctx, req)
	}

	return &envoy_service_ratelimit_v3.RateLimitResponse{
		OverallCode: envoy_service_ratelimit_v3.RateLimitResponse_OK,
		Statuses:    MakeResponse(envoy_service_ratelimit_v3.RateLimitResponse_OK, len(req.Descriptors)),
	}, nil
}

// FIXME: will be removed. Purely for debugging
func (r *RateLimiter) debugLog(req *envoy_service_ratelimit_v3.RateLimitRequest) {
	descriptors := map[string]string{}
	logger := slog.With("domain", req.Domain)

	for _, desc := range req.GetDescriptors() {
		for _, ent := range desc.Entries {
			descriptors[ent.Key] = ent.Value
		}
	}
	logger.Info("printing descriptors from authorize...")
	k := maps.Keys(descriptors)
	desc := iterutil.SortedUnion(func(a, b string) int {
		return strings.Compare(a, b)
	}, k)
	for key := range desc {
		slog.With(key, descriptors[key]).Info("got rate limit attribute")
	}
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
