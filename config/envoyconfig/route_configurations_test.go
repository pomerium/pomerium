package envoyconfig

import (
	"encoding/base64"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/config/envoyconfig/filemgr"
	"github.com/pomerium/pomerium/internal/testutil"
	"github.com/pomerium/pomerium/pkg/cryptutil"
)

func TestBuilder_buildMainRouteConfiguration(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
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
	b := New("connect", "grpc", "http", "debug", "metrics", filemgr.NewManager(), nil, true)
	routeConfiguration, err := b.buildMainRouteConfiguration(ctx, cfg)
	assert.NoError(t, err)
	testutil.AssertProtoJSONEqual(t, `{
		"name": "main",
		"validateClusters": false,
		"virtualHosts": [
			{
				"name": "catch-all",
				"domains": ["*"],
				"routes": [
					`+protojson.Format(b.buildControlPlanePathRoute(cfg.Options, "/ping"))+`,
					`+protojson.Format(b.buildControlPlanePathRoute(cfg.Options, "/healthz"))+`,
					`+protojson.Format(b.buildControlPlanePathRoute(cfg.Options, "/.pomerium"))+`,
					`+protojson.Format(b.buildControlPlanePrefixRoute(cfg.Options, "/.pomerium/"))+`,
					`+protojson.Format(b.buildControlPlanePathRoute(cfg.Options, "/.well-known/pomerium"))+`,
					`+protojson.Format(b.buildControlPlanePrefixRoute(cfg.Options, "/.well-known/pomerium/"))+`,
					{
						"name": "policy-0",
						"decorator": {
							"operation": "ingress: ${method} ${host}${path}",
							"propagate": false
						},
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
							"cluster": "route-5fbd81d8f19363f4",
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
										"route_checksum": "14103096999915755832",
										"route_id": "5fbd81d8f19363f4"
									}
								}
							}
						}
					},
					{
						"name": "policy-0",
						"decorator": {
							"operation": "ingress: ${method} ${host}${path}",
							"propagate": false
						},
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
							"cluster": "route-5fbd81d8f19363f4",
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
										"route_checksum": "14103096999915755832",
										"route_id": "5fbd81d8f19363f4"
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

func Test_getAllDomains(t *testing.T) {
	t.Parallel()

	cert, err := cryptutil.GenerateCertificate(nil, "*.unknown.example.com")
	require.NoError(t, err)
	certPEM, keyPEM, err := cryptutil.EncodeCertificate(cert)
	require.NoError(t, err)

	options := &config.Options{
		Addr:                          "127.0.0.1:9000",
		GRPCAddr:                      "127.0.0.1:9001",
		Services:                      "all",
		AuthenticateURLString:         "https://authenticate.example.com",
		AuthenticateInternalURLString: "https://authenticate.int.example.com",
		AuthorizeURLString:            "https://authorize.example.com:9001",
		DataBroker:                    config.DataBrokerOptions{ServiceURL: "https://cache.example.com:9001"},
		Policies: []config.Policy{
			{From: "http://a.example.com"},
			{From: "https://b.example.com"},
			{From: "https://c.example.com"},
			{From: "https://d.unknown.example.com"},
		},
		Cert: base64.StdEncoding.EncodeToString(certPEM),
		Key:  base64.StdEncoding.EncodeToString(keyPEM),
	}
	t.Run("routable", func(t *testing.T) {
		t.Run("http", func(t *testing.T) {
			actual, _, err := getAllRouteableHosts(options, "127.0.0.1:9000")
			require.NoError(t, err)
			expect := []string{
				"a.example.com",
				"a.example.com:80",
				"authenticate.example.com",
				"authenticate.example.com:443",
				"authenticate.int.example.com",
				"authenticate.int.example.com:443",
				"b.example.com",
				"b.example.com:443",
				"c.example.com",
				"c.example.com:443",
				"d.unknown.example.com",
				"d.unknown.example.com:443",
			}
			assert.Equal(t, expect, actual)
		})
		t.Run("grpc", func(t *testing.T) {
			actual, _, err := getAllRouteableHosts(options, "127.0.0.1:9001")
			require.NoError(t, err)
			expect := []string{
				"authorize.example.com:9001",
				"cache.example.com:9001",
			}
			assert.Equal(t, expect, actual)
		})
		t.Run("both", func(t *testing.T) {
			newOptions := *options
			newOptions.GRPCAddr = newOptions.Addr
			actual, _, err := getAllRouteableHosts(&newOptions, "127.0.0.1:9000")
			require.NoError(t, err)
			expect := []string{
				"a.example.com",
				"a.example.com:80",
				"authenticate.example.com",
				"authenticate.example.com:443",
				"authenticate.int.example.com",
				"authenticate.int.example.com:443",
				"authorize.example.com:9001",
				"b.example.com",
				"b.example.com:443",
				"c.example.com",
				"c.example.com:443",
				"cache.example.com:9001",
				"d.unknown.example.com",
				"d.unknown.example.com:443",
			}
			assert.Equal(t, expect, actual)
		})
	})

	t.Run("exclude default authenticate", func(t *testing.T) {
		options := config.NewDefaultOptions()
		options.Policies = []config.Policy{
			{From: "https://a.example.com"},
		}
		actual, _, err := getAllRouteableHosts(options, ":443")
		require.NoError(t, err)
		assert.Equal(t, []string{"a.example.com"}, actual)
	})
}

func Test_urlMatchesHost(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name      string
		sourceURL string
		host      string
		matches   bool
	}{
		{"no port", "http://example.com", "example.com", true},
		{"host http port", "http://example.com", "example.com:80", true},
		{"host https port", "https://example.com", "example.com:443", true},
		{"with port", "https://example.com:443", "example.com:443", true},
		{"url port", "https://example.com:443", "example.com", true},
		{"non standard port", "http://example.com:81", "example.com", false},
		{"non standard host port", "http://example.com:81", "example.com:80", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tc.matches, urlMatchesHost(mustParseURL(t, tc.sourceURL), tc.host),
				"urlMatchesHost(%s,%s)", tc.sourceURL, tc.host)
		})
	}
}
