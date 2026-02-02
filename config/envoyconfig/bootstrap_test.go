package envoyconfig

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/config/envoyconfig/filemgr"
	"github.com/pomerium/pomerium/internal/testutil"
)

func TestBuilder_BuildBootstrapAdmin(t *testing.T) {
	t.Setenv("TMPDIR", "/tmp")
	b := New("local-connect", "local-grpc", "local-http", "local-debug", "local-metrics", filemgr.NewManager(), nil, true)
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
						"path": "/tmp/`+config.DefaultEnvoyAdminSockName+`"
					}
				}
			}
		`, adminCfg)
	})
}

func TestBuilder_BuildBootstrapLayeredRuntime(t *testing.T) {
	t.Parallel()

	b := New("local-connect", "localhost:1111", "localhost:2222", "localhost:3333", "localhost:4444", filemgr.NewManager(), nil, true)
	staticCfg, err := b.BuildBootstrapLayeredRuntime(t.Context(), &config.Config{})
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
				},
				"tracing": {
					"opentelemetry": {
						"flush_interval_ms": 5000,
						"min_flush_spans": 512
					}
				}
			}
		}] }
	`, staticCfg)
}

func TestBuilder_BuildBootstrapStaticResources(t *testing.T) {
	t.Parallel()

	t.Run("valid", func(t *testing.T) {
		b := New("local-connect", "localhost:1111", "localhost:2222", "localhost:3333", "localhost:4444", filemgr.NewManager(), nil, true)
		staticCfg, err := b.BuildBootstrapStaticResources(t.Context(), &config.Config{}, false)
		assert.NoError(t, err)
		testutil.AssertProtoJSONEqual(t, `
			{
				"clusters": [
					{
						"name": "pomerium-control-plane-grpc",
						"type": "STATIC",
						"connectTimeout": "5s",
						"circuitBreakers": {
						  "thresholds": [{
						    "maxConnectionPools": 4294967295,
							"maxConnections": 4294967295,
							"maxPendingRequests": 4294967295,
							"maxRequests": 4294967295
						  }]
						},
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
		b := New("local-connect", "xyz:zyx", "localhost:2222", "localhost:3333", "localhost:4444", filemgr.NewManager(), nil, true)
		_, err := b.BuildBootstrapStaticResources(t.Context(), &config.Config{}, false)
		assert.Error(t, err)
	})
}

func TestBuilder_BuildBootstrapStatsConfig(t *testing.T) {
	t.Parallel()

	b := New("local-connect", "local-grpc", "local-http", "local-debug", "local-metrics", filemgr.NewManager(), nil, true)
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
	t.Parallel()

	b := New("local-connect", "localhost:1111", "localhost:2222", "localhost:3333", "localhost:4444", filemgr.NewManager(), nil, true)
	t.Run("OverloadManager", func(t *testing.T) {
		bootstrap, err := b.BuildBootstrap(t.Context(), &config.Config{
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
