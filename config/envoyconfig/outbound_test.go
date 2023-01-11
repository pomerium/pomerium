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
			"name": "pomerium-control-plane-grpc",
			"route": {
				"autoHostRewrite": true,
				"cluster": "pomerium-control-plane-grpc",
				"idleTimeout": "0s",
				"timeout": "0s"
			}
		}
	]`, routes)
}
