package ratelimit

import (
	"context"
	"log/slog"
	"maps"
	"strings"
	"sync"

	envoy_service_ratelimit_v3 "github.com/envoyproxy/go-control-plane/envoy/service/ratelimit/v3"
	oteltrace "go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/pomerium/pomerium/config"
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

	remoteSrvMu         *sync.RWMutex
	underlyingRemoteSrv envoy_service_ratelimit_v3.RateLimitServiceClient
	tracer              oteltrace.Tracer
}

func NewRateLimiter(
	traceProvider oteltrace.TracerProvider,
	impl envoy_service_ratelimit_v3.RateLimitServiceServer,
) *RateLimiter {
	return &RateLimiter{
		tracer:        traceProvider.Tracer(trace.PomeriumCoreTracer),
		remoteSrvMu:   &sync.RWMutex{},
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
		resp, err := r.underlyingSrv.ShouldRateLimit(ctx, req)
		if err != nil {
			return nil, err
		}
		if resp.OverallCode == envoy_service_ratelimit_v3.RateLimitResponse_UNKNOWN {
			// continue to remote server
		} else {
			return resp, err
		}
	}

	r.remoteSrvMu.RLock()
	cl := r.underlyingRemoteSrv
	r.remoteSrvMu.RUnlock()
	if cl != nil {
		return cl.ShouldRateLimit(ctx, &envoy_service_ratelimit_v3.RateLimitRequest{})
	}

	return &envoy_service_ratelimit_v3.RateLimitResponse{
		OverallCode: envoy_service_ratelimit_v3.RateLimitResponse_OK,
		Statuses:    makeResponse(envoy_service_ratelimit_v3.RateLimitResponse_OK, len(req.Descriptors)),
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

func makeResponse(code envoy_service_ratelimit_v3.RateLimitResponse_Code, n int) []*envoy_service_ratelimit_v3.RateLimitResponse_DescriptorStatus {
	ret := make([]*envoy_service_ratelimit_v3.RateLimitResponse_DescriptorStatus, n)

	for i := range n {
		ret[i] = &envoy_service_ratelimit_v3.RateLimitResponse_DescriptorStatus{
			Code: code,
		}
	}
	return ret
}

func (r *RateLimiter) OnConfigChange(_ context.Context, cfg *config.Config) error {
	r.remoteSrvMu.Lock()
	defer r.remoteSrvMu.Unlock()
	if cfg.Options.SSHRLSRemoteAddress != "" {
		// TODO : should do more address validation before this step
		cl, err := newRLSClient(cfg.Options.SSHRLSRemoteAddress)
		if err != nil {
			return err
		}
		r.underlyingRemoteSrv = cl
	}
	return nil
}

// FIXME: this will block and may prevent config changes in other places, needs rework
func newRLSClient(addr string) (envoy_service_ratelimit_v3.RateLimitServiceClient, error) {
	dialOpts := []grpc.DialOption{
		grpc.WithDisableServiceConfig(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(grpc.WaitForReady(true)),
	}

	cc, err := grpc.NewClient(addr, dialOpts...)
	if err != nil {
		return nil, err
	}
	return envoy_service_ratelimit_v3.NewRateLimitServiceClient(cc), nil
}
