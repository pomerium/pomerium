package envoyconfig

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/testutil"
)

func TestBuildTracingCluster(t *testing.T) {
	t.Run("datadog", func(t *testing.T) {
		c, err := buildTracingCluster(&config.Options{
			TracingProvider: "datadog",
		})
		require.NoError(t, err)
		testutil.AssertProtoJSONEqual(t, `
			{
				"name": "datadog-apm",
				"type": "STATIC",
				"connectTimeout": "5s",
				"loadAssignment": {
					"clusterName": "datadog-apm",
					"endpoints": [{
						"lbEndpoints": [{
							"endpoint": {
								"address": {
									"socketAddress": {
										"address": "127.0.0.1",
										"portValue": 8126
									}
								}
							}
						}]
					}]
				}
			}
		`, c)

		c, err = buildTracingCluster(&config.Options{
			TracingProvider:       "datadog",
			TracingDatadogAddress: "example.com:8126",
		})
		require.NoError(t, err)
		testutil.AssertProtoJSONEqual(t, `
			{
				"name": "datadog-apm",
				"type": "STRICT_DNS",
				"connectTimeout": "5s",
				"loadAssignment": {
					"clusterName": "datadog-apm",
					"endpoints": [{
						"lbEndpoints": [{
							"endpoint": {
								"address": {
									"socketAddress": {
										"address": "example.com",
										"portValue": 8126
									}
								}
							}
						}]
					}]
				}
			}
		`, c)
	})
	t.Run("zipkin", func(t *testing.T) {
		c, err := buildTracingCluster(&config.Options{
			TracingProvider: "zipkin",
			ZipkinEndpoint:  "https://example.com/api/v2/spans",
		})
		require.NoError(t, err)
		testutil.AssertProtoJSONEqual(t, `
			{
				"name": "zipkin",
				"type": "STRICT_DNS",
				"connectTimeout": "5s",
				"loadAssignment": {
					"clusterName": "zipkin",
					"endpoints": [{
						"lbEndpoints": [{
							"endpoint": {
								"address": {
									"socketAddress": {
										"address": "example.com",
										"portValue": 443
									}
								}
							}
						}]
					}]
				}
			}
		`, c)
	})
}

func TestBuildTracingHTTP(t *testing.T) {
	t.Run("datadog", func(t *testing.T) {
		h, err := buildTracingHTTP(&config.Options{
			TracingProvider: "datadog",
		})
		require.NoError(t, err)
		testutil.AssertProtoJSONEqual(t, `
			{
				"name": "envoy.tracers.datadog",
				"typedConfig": {
					"@type": "type.googleapis.com/envoy.config.trace.v3.DatadogConfig",
					"collectorCluster": "datadog-apm",
					"serviceName": "pomerium"
				}
			}
		`, h)
	})
	t.Run("zipkin", func(t *testing.T) {
		h, err := buildTracingHTTP(&config.Options{
			TracingProvider: "zipkin",
			ZipkinEndpoint:  "https://example.com/api/v2/spans",
		})
		require.NoError(t, err)
		testutil.AssertProtoJSONEqual(t, `
			{
				"name": "envoy.tracers.zipkin",
				"typedConfig": {
					"@type": "type.googleapis.com/envoy.config.trace.v3.ZipkinConfig",
					"collectorCluster": "zipkin",
					"collectorEndpoint": "/api/v2/spans",
					"collectorEndpointVersion": "HTTP_JSON"
				}
			}
		`, h)
	})
}
