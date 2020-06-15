package controlplane

import (
	"net/url"
	"testing"
	"time"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/testutil"
)

func Test_buildGRPCRoutes(t *testing.T) {
	routes := buildGRPCRoutes()
	testutil.AssertProtoJSONEqual(t, `
		[
			{
				"name": "pomerium-grpc",
				"match": {
					"grpc": {},
					"prefix": "/"
				},
				"route": {
					"cluster": "pomerium-control-plane-grpc"
				},
				"typedPerFilterConfig": {
					"envoy.filters.http.ext_authz": {
						"@type": "type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthzPerRoute",
						"disabled": true
					}
				}
			}
		]
	`, routes)
}

func Test_buildPomeriumHTTPRoutes(t *testing.T) {
	routes := buildPomeriumHTTPRoutes(&config.Options{
		Services:                 "all",
		AuthenticateURL:          mustParseURL("https://authenticate.example.com"),
		AuthenticateCallbackPath: "/oauth2/callback",
		ForwardAuthURL:           mustParseURL("https://forward-auth.example.com"),
	}, "authenticate.example.com")

	testutil.AssertProtoJSONEqual(t, `
		[
			{
				"name": "pomerium-path-/ping",
				"match": {
					"path": "/ping"
				},
				"route": {
					"cluster": "pomerium-control-plane-http"
				},
				"typedPerFilterConfig": {
					"envoy.filters.http.ext_authz": {
						"@type": "type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthzPerRoute",
						"disabled": true
					}
				}
			},
			{
				"name": "pomerium-path-/healthz",
				"match": {
					"path": "/healthz"
				},
				"route": {
					"cluster": "pomerium-control-plane-http"
				},
				"typedPerFilterConfig": {
					"envoy.filters.http.ext_authz": {
						"@type": "type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthzPerRoute",
						"disabled": true
					}
				}
			},
			{
				"name": "pomerium-path-/.pomerium",
				"match": {
					"path": "/.pomerium"
				},
				"route": {
					"cluster": "pomerium-control-plane-http"
				},
				"typedPerFilterConfig": {
					"envoy.filters.http.ext_authz": {
						"@type": "type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthzPerRoute",
						"disabled": true
					}
				}
			},
			{
				"name": "pomerium-prefix-/.pomerium/",
				"match": {
					"prefix": "/.pomerium/"
				},
				"route": {
					"cluster": "pomerium-control-plane-http"
				},
				"typedPerFilterConfig": {
					"envoy.filters.http.ext_authz": {
						"@type": "type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthzPerRoute",
						"disabled": true
					}
				}
			},
			{
				"name": "pomerium-path-/.well-known/pomerium",
				"match": {
					"path": "/.well-known/pomerium"
				},
				"route": {
					"cluster": "pomerium-control-plane-http"
				},
				"typedPerFilterConfig": {
					"envoy.filters.http.ext_authz": {
						"@type": "type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthzPerRoute",
						"disabled": true
					}
				}
			},
			{
				"name": "pomerium-prefix-/.well-known/pomerium/",
				"match": {
					"prefix": "/.well-known/pomerium/"
				},
				"route": {
					"cluster": "pomerium-control-plane-http"
				},
				"typedPerFilterConfig": {
					"envoy.filters.http.ext_authz": {
						"@type": "type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthzPerRoute",
						"disabled": true
					}
				}
			},
			{
				"name": "pomerium-path-/oauth2/callback",
				"match": {
					"path": "/oauth2/callback"
				},
				"route": {
					"cluster": "pomerium-control-plane-http"
				},
				"typedPerFilterConfig": {
					"envoy.filters.http.ext_authz": {
						"@type": "type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthzPerRoute",
						"disabled": true
					}
				}
			}
		]
	`, routes)
}

func Test_buildControlPlanePathRoute(t *testing.T) {
	route := buildControlPlanePathRoute("/hello/world")
	testutil.AssertProtoJSONEqual(t, `
		{
			"name": "pomerium-path-/hello/world",
			"match": {
				"path": "/hello/world"
			},
			"route": {
				"cluster": "pomerium-control-plane-http"
			},
			"typedPerFilterConfig": {
				"envoy.filters.http.ext_authz": {
					"@type": "type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthzPerRoute",
					"disabled": true
				}
			}
		}
	`, route)
}

func Test_buildControlPlanePrefixRoute(t *testing.T) {
	route := buildControlPlanePrefixRoute("/hello/world/")
	testutil.AssertProtoJSONEqual(t, `
		{
			"name": "pomerium-prefix-/hello/world/",
			"match": {
				"prefix": "/hello/world/"
			},
			"route": {
				"cluster": "pomerium-control-plane-http"
			},
			"typedPerFilterConfig": {
				"envoy.filters.http.ext_authz": {
					"@type": "type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthzPerRoute",
					"disabled": true
				}
			}
		}
	`, route)
}

func Test_buildPolicyRoutes(t *testing.T) {
	routes := buildPolicyRoutes(&config.Options{
		CookieName:             "pomerium",
		DefaultUpstreamTimeout: time.Second * 3,
		Policies: []config.Policy{
			{
				Source: &config.StringURL{URL: mustParseURL("https://ignore.example.com")},
			},
			{
				Source: &config.StringURL{URL: mustParseURL("https://example.com")},
			},
			{
				Source:             &config.StringURL{URL: mustParseURL("https://example.com")},
				Path:               "/some/path",
				AllowWebsockets:    true,
				PreserveHostHeader: true,
			},
			{
				Source:            &config.StringURL{URL: mustParseURL("https://example.com")},
				Prefix:            "/some/prefix/",
				SetRequestHeaders: map[string]string{"HEADER-KEY": "HEADER-VALUE"},
				UpstreamTimeout:   time.Minute,
			},
			{
				Source: &config.StringURL{URL: mustParseURL("https://example.com")},
				Regex:  `^/[a]+$`,
			},
			{
				Source:               &config.StringURL{URL: mustParseURL("https://example.com")},
				Prefix:               "/some/prefix/",
				RemoveRequestHeaders: []string{"HEADER-KEY"},
				UpstreamTimeout:      time.Minute,
			},
		},
	}, "example.com")

	testutil.AssertProtoJSONEqual(t, `
		[
			{
				"name": "policy-1",
				"match": {
					"prefix": "/"
				},
				"metadata": {
					"filterMetadata": {
						"envoy.filters.http.lua": {
							"remove_pomerium_authorization": true,
							"remove_pomerium_cookie": "pomerium"
						}
					}
				},
				"route": {
					"autoHostRewrite": true,
					"cluster": "policy-701142725541ce1f",
					"timeout": "3s",
					"upgradeConfigs": [{
						"enabled": false,
						"upgradeType": "websocket"
					}]
				}
			},
			{
				"name": "policy-2",
				"match": {
					"path": "/some/path"
				},
				"metadata": {
					"filterMetadata": {
						"envoy.filters.http.lua": {
							"remove_pomerium_authorization": true,
							"remove_pomerium_cookie": "pomerium"
						}
					}
				},
				"route": {
					"autoHostRewrite": false,
					"cluster": "policy-35b6cce9d52d36ed",
					"timeout": "0s",
					"upgradeConfigs": [{
						"enabled": true,
						"upgradeType": "websocket"
					}]
				}
			},
			{
				"name": "policy-3",
				"match": {
					"prefix": "/some/prefix/"
				},
				"metadata": {
					"filterMetadata": {
						"envoy.filters.http.lua": {
							"remove_pomerium_authorization": true,
							"remove_pomerium_cookie": "pomerium"
						}
					}
				},
				"route": {
					"autoHostRewrite": true,
					"cluster": "policy-8935ca8067709cf7",
					"timeout": "60s",
					"upgradeConfigs": [{
						"enabled": false,
						"upgradeType": "websocket"
					}]
				},
				"requestHeadersToAdd": [{
					"append": false,
					"header": {
						"key": "HEADER-KEY",
						"value": "HEADER-VALUE"
					}
				}]
			},
			{
				"name": "policy-4",
				"match": {
					"safeRegex": {
						"googleRe2": {},
						"regex": "^/[a]+$"
					}
				},
				"metadata": {
					"filterMetadata": {
						"envoy.filters.http.lua": {
							"remove_pomerium_authorization": true,
							"remove_pomerium_cookie": "pomerium"
						}
					}
				},
				"route": {
					"autoHostRewrite": true,
					"cluster": "policy-45c2908c3d6f0e52",
					"timeout": "3s",
					"upgradeConfigs": [{
						"enabled": false,
						"upgradeType": "websocket"
					}]
				}
			},
			{
				"name": "policy-5",
				"match": {
					"prefix": "/some/prefix/"
				},
				"metadata": {
					"filterMetadata": {
						"envoy.filters.http.lua": {
							"remove_pomerium_authorization": true,
							"remove_pomerium_cookie": "pomerium"
						}
					}
				},
				"route": {
					"autoHostRewrite": true,
					"cluster": "policy-8935ca8067709cf7",
					"timeout": "60s",
					"upgradeConfigs": [{
						"enabled": false,
						"upgradeType": "websocket"
					}]
				},
				"requestHeadersToRemove": ["HEADER-KEY"]
			}
		]
	`, routes)
}

func mustParseURL(str string) *url.URL {
	u, err := url.Parse(str)
	if err != nil {
		panic(err)
	}
	return u
}
