package envoyconfig

import (
	"testing"

	"github.com/pomerium/pomerium/internal/testutil"
)

func Test_buildOutboundRoutes(t *testing.T) {
	b := New("local-grpc", "local-http", "local-metrics", nil, nil)
	routes := b.buildOutboundRoutes()
	testutil.AssertProtoJSONEqual(t, `[
		{
			"match": {
				"grpc": {},
				"prefix": "/envoy.service.auth.v3.Authorization/"
			},
			"decorator": {
				"operation": "Outbound (grpc): pomerium-authorize /envoy.service.auth.v3.Authorization/"
			},
			"name": "pomerium-authorize",
			"route": {
				"autoHostRewrite": true,
				"cluster": "pomerium-authorize",
				"idleTimeout": "0s",
				"timeout": "0s"
			}
		},
		{
			"match": {
				"grpc": {},
				"prefix": "/databroker.DataBrokerService/"
			},
			"decorator": {
				"operation": "Outbound (grpc): pomerium-databroker /databroker.DataBrokerService/"
			},
			"name": "pomerium-databroker",
			"route": {
				"autoHostRewrite": true,
				"cluster": "pomerium-databroker",
				"idleTimeout": "0s",
				"timeout": "0s"
			}
		},
		{
			"match": {
				"grpc": {},
				"prefix": "/registry.Registry/"
			},
			"decorator": {
				"operation": "Outbound (grpc): pomerium-databroker /registry.Registry/"
			},
			"name": "pomerium-databroker",
			"route": {
				"autoHostRewrite": true,
				"cluster": "pomerium-databroker",
				"idleTimeout": "0s",
				"timeout": "0s"
			}
		},
		{
			"match": {
				"grpc": {},
				"prefix": "/"
			},
			"decorator": {
				"operation": "Outbound (grpc): pomerium-control-plane-grpc /"
			},
			"name": "pomerium-control-plane-grpc",
			"route": {
				"autoHostRewrite": true,
				"cluster": "pomerium-control-plane-grpc",
				"idleTimeout": "0s",
				"timeout": "0s"
			}
		},
		{
			"match": {
				"prefix": "/envoy/stats/prometheus"
			},
			"decorator": {
				"operation": "Outbound: envoy-metrics /envoy/stats/prometheus/*"
			},
			"name": "envoy-metrics",
			"route": {
				"cluster": "pomerium-envoy-admin",
				"prefixRewrite": "/stats/prometheus"
			}
		}
	]`, routes)
}
