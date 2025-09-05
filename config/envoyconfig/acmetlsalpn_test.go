package envoyconfig

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/testutil"
)

func TestBuilder_buildACMETLSALPNCluster(t *testing.T) {
	cfg := &config.Config{Options: config.NewDefaultOptions()}
	require.NoError(t, cfg.AllocateLocal())

	port, err := cfg.ACMETLSALPNListener.Address().Port()
	require.NoError(t, err)

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
									"portValue": `+fmt.Sprint(port)+`
								}
							}
						}
					}]
				}]
			}
		}`,
		b.buildACMETLSALPNCluster(cfg))
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
