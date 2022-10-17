package envoyconfig

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/config/envoyconfig/filemgr"
	"github.com/pomerium/pomerium/internal/testutil"
)

func TestBuilder_BuildBootstrapAdmin(t *testing.T) {
	b := New("local-grpc", "local-http", "local-metrics", filemgr.NewManager(), nil)
	t.Run("valid", func(t *testing.T) {
		adminCfg, err := b.BuildBootstrapAdmin(&config.Config{
			Options: &config.Options{
				EnvoyAdminAddress: "localhost:9901",
			},
		})
		assert.NoError(t, err)
		testutil.AssertProtoJSONEqual(t, `
			{
				"address": {
					"pipe": {
						"mode": 384,
						"path": "`+envoyAdminAddressPath+`"
					}
				}
			}
		`, adminCfg)
	})
}

func TestBuilder_BuildBootstrapLayeredRuntime(t *testing.T) {
	b := New("localhost:1111", "localhost:2222", "localhost:3333", filemgr.NewManager(), nil)
	staticCfg, err := b.BuildBootstrapLayeredRuntime()
	assert.NoError(t, err)
	testutil.AssertProtoJSONEqual(t, `
		{ "layers": [{
			"name": "static_layer_0",
			"staticLayer": {
				"overload": {
					"global_downstream_max_connections": 50000
				}
			}
		}] }
	`, staticCfg)
}

func TestBuilder_BuildBootstrapStaticResources(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		b := New("localhost:1111", "localhost:2222", "localhost:3333", filemgr.NewManager(), nil)
		staticCfg, err := b.BuildBootstrapStaticResources()
		assert.NoError(t, err)
		testutil.AssertProtoJSONEqual(t, `
			{
				"clusters": [
					{
						"name": "pomerium-control-plane-grpc",
						"type": "STATIC",
						"connectTimeout": "5s",
						"loadAssignment": {
							"clusterName": "pomerium-control-plane-grpc",
							"endpoints": [{
								"lbEndpoints": [{
									"endpoint": {
										"address": {
											"socketAddress":{
												"address": "127.0.0.1",
												"portValue": 1111
											}
										}
									}
								}]
							}]
						},
						"typedExtensionProtocolOptions": {
							"envoy.extensions.upstreams.http.v3.HttpProtocolOptions": {
								"@type": "type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions",
								"explicitHttpConfig": {
									"http2ProtocolOptions": {
										"allowConnect": true,
										"initialConnectionWindowSize": 1048576,
										"initialStreamWindowSize": 65536,
										"maxConcurrentStreams": 100
									}
								}
							}
						}
					}
				]
			}
		`, staticCfg)
	})
	t.Run("bad gRPC address", func(t *testing.T) {
		b := New("xyz:zyx", "localhost:2222", "localhost:3333", filemgr.NewManager(), nil)
		_, err := b.BuildBootstrapStaticResources()
		assert.Error(t, err)
	})
}

func TestBuilder_BuildBootstrapStatsConfig(t *testing.T) {
	b := New("local-grpc", "local-http", "local-metrics", filemgr.NewManager(), nil)
	t.Run("valid", func(t *testing.T) {
		statsCfg, err := b.BuildBootstrapStatsConfig(&config.Config{
			Options: &config.Options{
				Services: "all",
			},
		})
		assert.NoError(t, err)
		testutil.AssertProtoJSONEqual(t, `
			{
				"statsTags": [{
					"tagName": "service",
					"fixedValue": "pomerium"
				}]
			}
		`, statsCfg)
	})
}
