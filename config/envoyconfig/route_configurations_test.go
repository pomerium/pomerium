package envoyconfig

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/config/envoyconfig/filemgr"
	"github.com/pomerium/pomerium/internal/testutil"
	"github.com/pomerium/pomerium/pkg/cryptutil"
)

func TestBuilder_buildMainRouteConfiguration(t *testing.T) {
	t.Parallel()

	cfg := &config.Config{Options: &config.Options{
		CookieName:             "pomerium",
		DefaultUpstreamTimeout: time.Second * 3,
		SharedKey:              cryptutil.NewBase64Key(),
		Services:               "proxy",
		Policies: []config.Policy{
			{
				From: "https://*.example.com",
				To:   mustParseWeightedURLs(t, "https://www.example.com"),
			},
		},
	}}
	b := BuilderOptions{
		LocalGRPCAddress:    "grpc",
		LocalHTTPAddress:    "http",
		LocalMetricsAddress: "metrics",
		FileManager:         filemgr.NewManager(),
		ReproxyHandler:      nil,
	}
	sb := b.NewForConfig(cfg)
	routeConfiguration, err := sb.buildMainRouteConfiguration()
	assert.NoError(t, err)
	testutil.AssertProtoJSONEqual(t, `{
		"name": "main",
		"validateClusters": false,
		"virtualHosts": [
			{
				"name": "catch-all",
				"domains": ["*"],
				"routes": [
					`+protojson.Format(sb.buildControlPlanePathRoute("/ping"))+`,
					`+protojson.Format(sb.buildControlPlanePathRoute("/healthz"))+`,
					`+protojson.Format(sb.buildControlPlanePathRoute("/.pomerium"))+`,
					`+protojson.Format(sb.buildControlPlanePrefixRoute("/.pomerium/"))+`,
					`+protojson.Format(sb.buildControlPlanePathRoute("/.well-known/pomerium"))+`,
					`+protojson.Format(sb.buildControlPlanePrefixRoute("/.well-known/pomerium/"))+`,
					{
						"name": "policy-0",
						"match": {
							"headers": [
								{ "name": ":authority", "stringMatch": { "safeRegex": { "regex": "^(.*)\\.example\\.com$" } }}
							],
							"prefix": "/"
						},
						"metadata": {
							"filterMetadata": {
								"envoy.filters.http.lua": {
									"remove_impersonate_headers": false,
									"remove_pomerium_authorization": true,
									"remove_pomerium_cookie": "pomerium",
									"rewrite_response_headers": []
								}
							}
						},
						"requestHeadersToRemove": [
							"x-pomerium-jwt-assertion",
							"x-pomerium-jwt-assertion-for",
							"x-pomerium-reproxy-policy",
							"x-pomerium-reproxy-policy-hmac"
						],
						"responseHeadersToAdd": [
							{ "appendAction": "OVERWRITE_IF_EXISTS_OR_ADD", "header": { "key": "X-Frame-Options", "value": "SAMEORIGIN" } },
							{ "appendAction": "OVERWRITE_IF_EXISTS_OR_ADD", "header": { "key": "X-XSS-Protection", "value": "1; mode=block" } }
						],
						"route": {
							"autoHostRewrite": true,
							"cluster": "route-5d678ee30d16332b",
							"hashPolicy": [
								{ "header": { "headerName": "x-pomerium-routing-key" }, "terminal": true },
								{ "connectionProperties": { "sourceIp": true }, "terminal": true }
							],
							"timeout": "3s",
							"upgradeConfigs": [
								{ "enabled": false, "upgradeType": "websocket" },
								{ "enabled": false, "upgradeType": "spdy/3.1" }
							]
						},
						"typedPerFilterConfig": {
							"envoy.filters.http.ext_authz": {
								"@type": "type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthzPerRoute",
								"checkSettings": {
									"contextExtensions": {
										"internal": "false",
										"route_id": "6730505273956774699"
									}
								}
							}
						}
					},
					{
						"name": "policy-0",
						"match": {
							"headers": [
								{ "name": ":authority", "stringMatch": { "safeRegex": { "regex": "^(.*)\\.example\\.com:443$" } }}
							],
							"prefix": "/"
						},
						"metadata": {
							"filterMetadata": {
								"envoy.filters.http.lua": {
									"remove_impersonate_headers": false,
									"remove_pomerium_authorization": true,
									"remove_pomerium_cookie": "pomerium",
									"rewrite_response_headers": []
								}
							}
						},
						"requestHeadersToRemove": [
							"x-pomerium-jwt-assertion",
							"x-pomerium-jwt-assertion-for",
							"x-pomerium-reproxy-policy",
							"x-pomerium-reproxy-policy-hmac"
						],
						"responseHeadersToAdd": [
							{ "appendAction": "OVERWRITE_IF_EXISTS_OR_ADD", "header": { "key": "X-Frame-Options", "value": "SAMEORIGIN" } },
							{ "appendAction": "OVERWRITE_IF_EXISTS_OR_ADD", "header": { "key": "X-XSS-Protection", "value": "1; mode=block" } }
						],
						"route": {
							"autoHostRewrite": true,
							"cluster": "route-5d678ee30d16332b",
							"hashPolicy": [
								{ "header": { "headerName": "x-pomerium-routing-key" }, "terminal": true },
								{ "connectionProperties": { "sourceIp": true }, "terminal": true }
							],
							"timeout": "3s",
							"upgradeConfigs": [
								{ "enabled": false, "upgradeType": "websocket" },
								{ "enabled": false, "upgradeType": "spdy/3.1" }
							]
						},
						"typedPerFilterConfig": {
							"envoy.filters.http.ext_authz": {
								"@type": "type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthzPerRoute",
								"checkSettings": {
									"contextExtensions": {
										"internal": "false",
										"route_id": "6730505273956774699"
									}
								}
							}
						}
					}
				]
			}
		]

	}`, routeConfiguration)
}
