package envoy

import (
	"context"

	envoy_config_bootstrap_v3 "github.com/envoyproxy/go-control-plane/envoy/config/bootstrap/v3"
)

type ResourceMonitor interface {
	Run(ctx context.Context, envoyPid int) error
	ApplyBootstrapConfig(bootstrap *envoy_config_bootstrap_v3.Bootstrap)
}
