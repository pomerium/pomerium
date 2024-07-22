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
	b := BuilderOptions{
		LocalGRPCAddress:    "local-grpc",
		LocalHTTPAddress:    "local-http",
		LocalMetricsAddress: "local-metrics",
		FileManager:         filemgr.NewManager(),
		ReproxyHandler:      nil,
	}
	t.Run("valid", func(t *testing.T) {
		adminCfg, err := b.NewForConfig(&config.Config{
			Options: &config.Options{
				EnvoyAdminAddress: "localhost:9901",
			},
		}).BuildBootstrapAdmin()
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
	b := BuilderOptions{
		LocalGRPCAddress:    "localhost:1111",
		LocalHTTPAddress:    "localhost:2222",
		LocalMetricsAddress: "localhost:3333",
		FileManager:         filemgr.NewManager(),
		ReproxyHandler:      nil,
	}
	staticCfg, err := b.NewForConfig(&config.Config{}).BuildBootstrapLayeredRuntime()
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
		b := BuilderOptions{
			LocalGRPCAddress:    "localhost:1111",
			LocalHTTPAddress:    "localhost:2222",
			LocalMetricsAddress: "localhost:3333",
			FileManager:         filemgr.NewManager(),
			ReproxyHandler:      nil,
		}
		staticCfg, err := b.NewForConfig(&config.Config{}).BuildBootstrapStaticResources(context.Background(), false)
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
		b := BuilderOptions{
			LocalGRPCAddress:    "xyz:zyx",
			LocalHTTPAddress:    "localhost:2222",
			LocalMetricsAddress: "localhost:3333",
			FileManager:         filemgr.NewManager(),
			ReproxyHandler:      nil,
		}
		_, err := b.NewForConfig(&config.Config{}).BuildBootstrapStaticResources(context.Background(), false)
		assert.Error(t, err)
	})
}

func TestBuilder_BuildBootstrapStatsConfig(t *testing.T) {
	b := BuilderOptions{
		LocalGRPCAddress:    "local-grpc",
		LocalHTTPAddress:    "local-http",
		LocalMetricsAddress: "local-metrics",
		FileManager:         filemgr.NewManager(),
		ReproxyHandler:      nil,
	}
	t.Run("valid", func(t *testing.T) {
		statsCfg, err := b.NewForConfig(&config.Config{
			Options: &config.Options{
				Services: "all",
			},
		}).BuildBootstrapStatsConfig()
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
	b := BuilderOptions{
		LocalGRPCAddress:    "localhost:1111",
		LocalHTTPAddress:    "localhost:2222",
		LocalMetricsAddress: "localhost:3333",
		FileManager:         filemgr.NewManager(),
		ReproxyHandler:      nil,
	}
	t.Run("OverloadManager", func(t *testing.T) {
		bootstrap, err := b.NewForConfig(&config.Config{
			Options: &config.Options{
				EnvoyAdminAddress: "localhost:9901",
			},
		}).BuildBootstrap(context.Background(), false)
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
