package envoyconfig

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/config/envoyconfig/filemgr"
	"github.com/pomerium/pomerium/internal/testutil"
)

func TestBuilder_BuildBootstrapAdmin(t *testing.T) {
	t.Setenv("TMPDIR", "/tmp")
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
						"path": "/tmp/`+envoyAdminAddressSockName+`"
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
				"re2": {
					"max_program_size": {
						"error_level": 1048576,
						"warn_level": 1024
					}
				}
			}
		}] }
	`, staticCfg)
}

func TestBuilder_BuildBootstrapStaticResources(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		b := New("localhost:1111", "localhost:2222", "localhost:3333", filemgr.NewManager(), nil)
		staticCfg, err := b.BuildBootstrapStaticResources(context.Background(), &config.Config{}, false)
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
		_, err := b.BuildBootstrapStaticResources(context.Background(), &config.Config{}, false)
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

func TestBuilder_BuildBootstrap(t *testing.T) {
	b := New("localhost:1111", "localhost:2222", "localhost:3333", filemgr.NewManager(), nil)
	t.Run("OverloadManager", func(t *testing.T) {
		bootstrap, err := b.BuildBootstrap(context.Background(), &config.Config{
			Options: &config.Options{
				EnvoyAdminAddress: "localhost:9901",
			},
		}, false)
		assert.NoError(t, err)
		testutil.AssertProtoJSONEqual(t, `
			{
				"resourceMonitors": [
					{
						"name": "envoy.resource_monitors.global_downstream_max_connections",
						"typedConfig": {
							"@type": "type.googleapis.com/envoy.extensions.resource_monitors.downstream_connections.v3.DownstreamConnectionsConfig",
							"maxActiveDownstreamConnections": "50000"
						}
					}
				]
			}
		`, bootstrap.OverloadManager)
	})
}
