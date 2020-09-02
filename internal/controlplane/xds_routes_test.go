package controlplane

import (
	"fmt"
	"testing"
	"time"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/testutil"
)

func policyNameFunc() func(*config.Policy) string {
	i := 0
	return func(*config.Policy) string {
		i++
		return fmt.Sprintf("policy-%d", i)
	}
}

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
	routeString := func(typ, name string) string {
		return `{
				"name": "pomerium-` + typ + `-` + name + `",
				"match": {
					"` + typ + `": "` + name + `"
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
			}`
	}

	t.Run("authenticate", func(t *testing.T) {
		options := &config.Options{
			Services:                 "all",
			AuthenticateURL:          mustParseURL("https://authenticate.example.com"),
			AuthenticateCallbackPath: "/oauth2/callback",
			ForwardAuthURL:           mustParseURL("https://forward-auth.example.com"),
		}
		routes := buildPomeriumHTTPRoutes(options, "authenticate.example.com")

		testutil.AssertProtoJSONEqual(t, `[
			`+routeString("path", "/ping")+`,
			`+routeString("path", "/healthz")+`,
			`+routeString("path", "/.pomerium")+`,
			`+routeString("prefix", "/.pomerium/")+`,
			`+routeString("path", "/.well-known/pomerium")+`,
			`+routeString("prefix", "/.well-known/pomerium/")+`,
			`+routeString("path", "/robots.txt")+`,
			`+routeString("path", "/oauth2/callback")+`
		]`, routes)
	})

	t.Run("with robots", func(t *testing.T) {
		options := &config.Options{
			Services:                 "all",
			AuthenticateURL:          mustParseURL("https://authenticate.example.com"),
			AuthenticateCallbackPath: "/oauth2/callback",
			ForwardAuthURL:           mustParseURL("https://forward-auth.example.com"),
			Policies: []config.Policy{{
				From: "https://from.example.com",
				To:   "https://to.example.com",
			}},
		}
		_ = options.Policies[0].Validate()
		routes := buildPomeriumHTTPRoutes(options, "from.example.com")

		testutil.AssertProtoJSONEqual(t, `[
			`+routeString("path", "/ping")+`,
			`+routeString("path", "/healthz")+`,
			`+routeString("path", "/.pomerium")+`,
			`+routeString("prefix", "/.pomerium/")+`,
			`+routeString("path", "/.well-known/pomerium")+`,
			`+routeString("prefix", "/.well-known/pomerium/")+`,
			`+routeString("path", "/robots.txt")+`
		]`, routes)
	})

	t.Run("without robots", func(t *testing.T) {
		options := &config.Options{
			Services:                 "all",
			AuthenticateURL:          mustParseURL("https://authenticate.example.com"),
			AuthenticateCallbackPath: "/oauth2/callback",
			ForwardAuthURL:           mustParseURL("https://forward-auth.example.com"),
			Policies: []config.Policy{{
				From:                             "https://from.example.com",
				To:                               "https://to.example.com",
				AllowPublicUnauthenticatedAccess: true,
			}},
		}
		_ = options.Policies[0].Validate()
		routes := buildPomeriumHTTPRoutes(options, "from.example.com")

		testutil.AssertProtoJSONEqual(t, `[
			`+routeString("path", "/ping")+`,
			`+routeString("path", "/healthz")+`,
			`+routeString("path", "/.pomerium")+`,
			`+routeString("prefix", "/.pomerium/")+`,
			`+routeString("path", "/.well-known/pomerium")+`,
			`+routeString("prefix", "/.well-known/pomerium/")+`
		]`, routes)
	})
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
	defer func(f func(*config.Policy) string) {
		getPolicyName = f
	}(getPolicyName)
	getPolicyName = policyNameFunc()
	routes := buildPolicyRoutes(&config.Options{
		CookieName:             "pomerium",
		DefaultUpstreamTimeout: time.Second * 3,
		Policies: []config.Policy{
			{
				Source:              &config.StringURL{URL: mustParseURL("https://ignore.example.com")},
				PassIdentityHeaders: true,
			},
			{
				Source:              &config.StringURL{URL: mustParseURL("https://example.com")},
				PassIdentityHeaders: true,
			},
			{
				Source:              &config.StringURL{URL: mustParseURL("https://example.com")},
				Path:                "/some/path",
				AllowWebsockets:     true,
				PreserveHostHeader:  true,
				PassIdentityHeaders: true,
			},
			{
				Source:              &config.StringURL{URL: mustParseURL("https://example.com")},
				Prefix:              "/some/prefix/",
				SetRequestHeaders:   map[string]string{"HEADER-KEY": "HEADER-VALUE"},
				UpstreamTimeout:     time.Minute,
				PassIdentityHeaders: true,
			},
			{
				Source:              &config.StringURL{URL: mustParseURL("https://example.com")},
				Regex:               `^/[a]+$`,
				PassIdentityHeaders: true,
			},
			{
				Source:               &config.StringURL{URL: mustParseURL("https://example.com")},
				Prefix:               "/some/prefix/",
				RemoveRequestHeaders: []string{"HEADER-KEY"},
				UpstreamTimeout:      time.Minute,
				PassIdentityHeaders:  true,
			},
			{
				Source:              &config.StringURL{URL: mustParseURL("https://example.com")},
				Path:                "/some/path",
				AllowSPDY:           true,
				PreserveHostHeader:  true,
				PassIdentityHeaders: true,
			},
			{
				Source:              &config.StringURL{URL: mustParseURL("https://example.com")},
				Path:                "/some/path",
				AllowSPDY:           true,
				AllowWebsockets:     true,
				PreserveHostHeader:  true,
				PassIdentityHeaders: true,
			},
			{
				Source:              &config.StringURL{URL: mustParseURL("https://example.com")},
				Path:                "/websocket-timeout",
				AllowWebsockets:     true,
				PreserveHostHeader:  true,
				PassIdentityHeaders: true,
				UpstreamTimeout:     time.Second * 10,
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
					"cluster": "policy-1",
					"timeout": "3s",
					"upgradeConfigs": [
						{ "enabled": false, "upgradeType": "websocket"},
						{ "enabled": false, "upgradeType": "spdy/3.1"}
					]
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
					"cluster": "policy-2",
					"timeout": "0s",
					"upgradeConfigs": [
						{ "enabled": true, "upgradeType": "websocket"},
						{ "enabled": false, "upgradeType": "spdy/3.1"}
					]
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
					"cluster": "policy-3",
					"timeout": "60s",
					"upgradeConfigs": [
						{ "enabled": false, "upgradeType": "websocket"},
						{ "enabled": false, "upgradeType": "spdy/3.1"}
					]
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
					"cluster": "policy-4",
					"timeout": "3s",
					"upgradeConfigs": [
						{ "enabled": false, "upgradeType": "websocket"},
						{ "enabled": false, "upgradeType": "spdy/3.1"}
					]
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
					"cluster": "policy-5",
					"timeout": "60s",
					"upgradeConfigs": [
						{ "enabled": false, "upgradeType": "websocket"},
						{ "enabled": false, "upgradeType": "spdy/3.1"}
					]
				},
				"requestHeadersToRemove": ["HEADER-KEY"]
			},
			{
				"name": "policy-6",
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
					"cluster": "policy-6",
					"timeout": "3s",
					"upgradeConfigs": [
						{ "enabled": false, "upgradeType": "websocket"},
						{ "enabled": true, "upgradeType": "spdy/3.1"}
					]
				}
			},
			{
				"name": "policy-7",
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
					"cluster": "policy-7",
					"timeout": "0s",
					"upgradeConfigs": [
						{ "enabled": true, "upgradeType": "websocket"},
						{ "enabled": true, "upgradeType": "spdy/3.1"}
					]
				}
			},
			{
				"name": "policy-8",
				"match": {
					"path": "/websocket-timeout"
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
					"cluster": "policy-8",
					"timeout": "10s",
					"upgradeConfigs": [
						{ "enabled": true, "upgradeType": "websocket"},
						{ "enabled": false, "upgradeType": "spdy/3.1"}
					]
				}
			}
		]
	`, routes)
}

// Make sure default Headers are set for response.
// See also https://github.com/pomerium/pomerium/issues/901
func TestAddOptionsHeadersToResponse(t *testing.T) {
	defer func(f func(*config.Policy) string) {
		getPolicyName = f
	}(getPolicyName)
	getPolicyName = policyNameFunc()
	routes := buildPolicyRoutes(&config.Options{
		CookieName:             "pomerium",
		DefaultUpstreamTimeout: time.Second * 3,
		Policies: []config.Policy{
			{
				Source:              &config.StringURL{URL: mustParseURL("https://example.com")},
				PassIdentityHeaders: true,
			},
		},
		Headers: map[string]string{"Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload"},
	}, "example.com")

	testutil.AssertProtoJSONEqual(t, `
		[
			{
				"name": "policy-0",
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
					"cluster": "policy-1",
					"timeout": "3s",
					"upgradeConfigs": [
						{ "enabled": false, "upgradeType": "websocket"},
						{ "enabled": false, "upgradeType": "spdy/3.1"}
					]
				},
				"responseHeadersToAdd": [{
					"append": false,
					"header": {
						"key": "Strict-Transport-Security",
						"value": "max-age=31536000; includeSubDomains; preload"
					}
				}]
			}
		]
	`, routes)
}

func Test_buildPolicyRoutesWithDestinationPath(t *testing.T) {
	defer func(f func(*config.Policy) string) {
		getPolicyName = f
	}(getPolicyName)
	getPolicyName = policyNameFunc()
	routes := buildPolicyRoutes(&config.Options{
		CookieName:             "pomerium",
		DefaultUpstreamTimeout: time.Second * 3,
		Policies: []config.Policy{
			{
				Source:              &config.StringURL{URL: mustParseURL("https://example.com")},
				Destination:         mustParseURL("https://foo.example.com/bar"),
				PassIdentityHeaders: true,
			},
		},
	}, "example.com")

	testutil.AssertProtoJSONEqual(t, `
		[
			{
				"name": "policy-0",
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
					"prefixRewrite": "/bar",
					"cluster": "policy-1",
					"timeout": "3s",
					"upgradeConfigs": [
						{ "enabled": false, "upgradeType": "websocket"},
						{ "enabled": false, "upgradeType": "spdy/3.1"}
					]
				}
			}
		]
	`, routes)
}
