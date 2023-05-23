package envoyconfig

import (
	"context"
	"strings"
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

	ctx := context.Background()
	cfg := &config.Config{Options: &config.Options{
		CookieName:             "pomerium",
		DefaultUpstreamTimeout: time.Second * 3,
		SharedKey:              cryptutil.NewBase64Key(),
		Services:               "proxy",
		Policies: []config.Policy{
			{
				From: "https://*.example.com",
			},
			{
				From: "https://foo.*.example.com",
			},
		},
	}}
	b := New("grpc", "http", "metrics", filemgr.NewManager(), nil)
	routeConfiguration, err := b.buildMainRouteConfiguration(ctx, cfg)
	assert.NoError(t, err)
	commonRoutes := strings.Join([]string{
		protojson.Format(b.buildControlPlanePathRoute(cfg.Options, "/.pomerium/jwt", true, false)),
		protojson.Format(b.buildControlPlanePathRoute(cfg.Options, "/.pomerium/webauthn", true, false)),
		protojson.Format(b.buildControlPlanePathRoute(cfg.Options, "/ping", false, false)),
		protojson.Format(b.buildControlPlanePathRoute(cfg.Options, "/healthz", false, false)),
		protojson.Format(b.buildControlPlanePathRoute(cfg.Options, "/.pomerium", false, false)),
		protojson.Format(b.buildControlPlanePrefixRoute(cfg.Options, "/.pomerium/", false, false)),
		protojson.Format(b.buildControlPlanePathRoute(cfg.Options, "/.well-known/pomerium", false, false)),
		protojson.Format(b.buildControlPlanePrefixRoute(cfg.Options, "/.well-known/pomerium/", false, false)),
		protojson.Format(b.buildControlPlanePathRoute(cfg.Options, "/robots.txt", false, false)),
	}, ",\n")
	const commonRouteConfig = `"metadata": {
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
							"cluster": "route-0",
							"hashPolicy": [
								{ "header": { "headerName": "x-pomerium-routing-key" }, "terminal": true },
								{ "connectionProperties": { "sourceIp": true }, "terminal": true }
							],
							"timeout": "3s",
							"upgradeConfigs": [
								{ "enabled": false, "upgradeType": "websocket" },
								{ "enabled": false, "upgradeType": "spdy/3.1" }
							]
						}`
	testutil.AssertProtoJSONEqual(t, `{
		"name": "main",
		"validateClusters": false,
		"virtualHosts": [
			{
				"name": "*.example.com",
				"domains": ["*.example.com"],
				"routes": [
					`+commonRoutes+`,
					{
						"name": "policy-0",
						"match": {
							"prefix": "/"
						},
						`+commonRouteConfig+`
					}
				]
			},
			{
				"name": "*.example.com:443",
				"domains": ["*.example.com:443"],
				"routes": [
					`+commonRoutes+`,
					{
						"name": "policy-0",
						"match": {
							"prefix": "/"
						},
						`+commonRouteConfig+`
					}
				]
			},
			{
				"name": "catch-all",
				"domains": ["*"],
				"routes": [
					`+commonRoutes+`,
					{
						"name": "policy-1",
						"match": {
							"headers": [
								{
									"name": ":authority",
									"stringMatch": {
										"safeRegex": {
											"regex": "^foo\\.(.*)\\.example\\.com$"
										}
									}
								}
							],
							"prefix": "/"
						},
						`+commonRouteConfig+`
					},
					{
						"name": "policy-1",
						"match": {
							"headers": [
								{
									"name": ":authority",
									"stringMatch": {
										"safeRegex": {
											"regex": "^foo\\.(.*)\\.example\\.com:443$"
										}
									}
								}
							],
							"prefix": "/"
						},
						`+commonRouteConfig+`
					}
				]
			}
		]
	}`, routeConfiguration)
}
