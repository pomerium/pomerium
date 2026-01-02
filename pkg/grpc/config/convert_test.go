package config_test

import (
	"testing"
	"time"

	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	configpb "github.com/pomerium/pomerium/pkg/grpc/config"
)

func TestToEnvoy(t *testing.T) {
	t.Parallel()

	expect := &envoy_config_core_v3.HealthCheck{
		Timeout:         durationpb.New(time.Second * 3),
		ReuseConnection: wrapperspb.Bool(true),
	}
	actual := (&configpb.HealthCheck{
		Timeout:         durationpb.New(time.Second * 3),
		ReuseConnection: wrapperspb.Bool(true),
	}).ToEnvoy()

	assert.Empty(t, cmp.Diff(expect, actual, protocmp.Transform()))
}
