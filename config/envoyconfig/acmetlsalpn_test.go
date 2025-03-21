package envoyconfig

import (
	"testing"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/testutil"
)

func TestBuilder_buildACMETLSALPNCluster(t *testing.T) {
	b := New("local-grpc", "local-http", "local-metrics", nil, nil, true)
	testutil.AssertProtoJSONEqual(t,
		`{
			"name": "pomerium-acme-tls-alpn",
			"loadAssignment": {
				"clusterName": "pomerium-acme-tls-alpn",
				"endpoints": [{
					"lbEndpoints": [{
						"endpoint": {
							"address": {
								"socketAddress": {
									"address": "127.0.0.1",
									"portValue": 1234
								}
							}
						}
					}]
				}]
			}
		}`,
		b.buildACMETLSALPNCluster(&config.Config{
			ACMETLSALPNPort: "1234",
		}))
}

func TestBuilder_buildACMETLSALPNFilterChain(t *testing.T) {
	b := New("local-grpc", "local-http", "local-metrics", nil, nil, true)
	testutil.AssertProtoJSONEqual(t,
		`{
			"filterChainMatch": {
				"applicationProtocols": ["acme-tls/1"]
			},
			"filters": [{
				"name": "tcp_proxy",
				"typedConfig": {
					"@type": "type.googleapis.com/envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy",
					"cluster": "pomerium-acme-tls-alpn",
					"statPrefix": "acme_tls_alpn"
				}
			}]
		}`,
		b.buildACMETLSALPNFilterChain())
}
