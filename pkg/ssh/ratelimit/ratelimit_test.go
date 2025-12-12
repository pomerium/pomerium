package ratelimit_test

import (
	"context"
	"fmt"
	"testing"

	envoy_common_ratelimit_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/common/ratelimit/v3"
	envoy_service_ratelimit_v3 "github.com/envoyproxy/go-control-plane/envoy/service/ratelimit/v3"
	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/pomerium/pomerium/pkg/ssh/ratelimit"
)

func TestRateLimiter(t *testing.T) {
	t.Run("default", func(t *testing.T) {
		rls := ratelimit.NewRateLimiter(noop.NewTracerProvider(), nil)

		resp, err := rls.ShouldRateLimit(t.Context(), &envoy_service_ratelimit_v3.RateLimitRequest{
			Domain: "a",
			Descriptors: []*envoy_common_ratelimit_v3.RateLimitDescriptor{
				{
					Entries: []*envoy_common_ratelimit_v3.RateLimitDescriptor_Entry{
						{
							Key:   "foo",
							Value: "bar",
						},
					},
				},
			},
		})
		assert.NoError(t, err)
		assert.NotNil(t, resp)
		assert.Equal(t, envoy_service_ratelimit_v3.RateLimitResponse_OK, resp.OverallCode)
		assert.Equal(t, 1, len(resp.Statuses))

		for idx, st := range resp.Statuses {
			assert.Equal(t, envoy_service_ratelimit_v3.RateLimitResponse_OK, st.Code, fmt.Sprintf("response status %d does not match", idx))
		}
	})

	t.Run("override", func(t *testing.T) {
		rlsBad := ratelimit.NewRateLimiter(noop.NewTracerProvider(), &fakeRateLimitServer{})
		resp, err := rlsBad.ShouldRateLimit(t.Context(), &envoy_service_ratelimit_v3.RateLimitRequest{
			Domain: "a",
			Descriptors: []*envoy_common_ratelimit_v3.RateLimitDescriptor{
				{
					Entries: []*envoy_common_ratelimit_v3.RateLimitDescriptor_Entry{
						{
							Key:   "foo",
							Value: "bar",
						},
					},
				},
			},
		})
		assert.NoError(t, err)
		assert.NotNil(t, resp)
		assert.Equal(t, envoy_service_ratelimit_v3.RateLimitResponse_OVER_LIMIT, resp.OverallCode)
		assert.Equal(t, 1, len(resp.Statuses))

		for idx, st := range resp.Statuses {
			assert.Equal(t, envoy_service_ratelimit_v3.RateLimitResponse_OVER_LIMIT, st.Code, fmt.Sprintf("response status %d does not match", idx))
		}
	})
}

type fakeRateLimitServer struct{}

func (f *fakeRateLimitServer) ShouldRateLimit(
	_ context.Context,
	req *envoy_service_ratelimit_v3.RateLimitRequest,
) (*envoy_service_ratelimit_v3.RateLimitResponse, error) {
	return &envoy_service_ratelimit_v3.RateLimitResponse{
		OverallCode: envoy_service_ratelimit_v3.RateLimitResponse_OVER_LIMIT,
		Statuses:    ratelimit.MakeResponse(envoy_service_ratelimit_v3.RateLimitResponse_OVER_LIMIT, len(req.Descriptors)),
	}, nil
}
