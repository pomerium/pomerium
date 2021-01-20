package controlplane

import (
	"fmt"
	"testing"
	"time"

	envoy_config_route_v3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/proto"

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
	routeString := func(typ, name string, protected bool) string {
		str := `{
				"name": "pomerium-` + typ + `-` + name + `",
				"match": {
					"` + typ + `": "` + name + `"
				},
				"route": {
					"cluster": "pomerium-control-plane-http"
				}
			`
		if !protected {
			str += `,
				"typedPerFilterConfig": {
					"envoy.filters.http.ext_authz": {
						"@type": "type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthzPerRoute",
						"disabled": true
					}
				}
			`
		}
		str += "}"
		return str
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
			`+routeString("path", "/.pomerium/jwt", true)+`,
			`+routeString("path", "/ping", false)+`,
			`+routeString("path", "/healthz", false)+`,
			`+routeString("path", "/.pomerium/admin", true)+`,
			`+routeString("prefix", "/.pomerium/admin/", true)+`,
			`+routeString("path", "/.pomerium", false)+`,
			`+routeString("prefix", "/.pomerium/", false)+`,
			`+routeString("path", "/.well-known/pomerium", false)+`,
			`+routeString("prefix", "/.well-known/pomerium/", false)+`,
			`+routeString("path", "/robots.txt", false)+`,
			`+routeString("path", "/oauth2/callback", false)+`
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
				To:   config.StringSlice{"https://to.example.com"},
			}},
		}
		_ = options.Policies[0].Validate()
		routes := buildPomeriumHTTPRoutes(options, "from.example.com")

		testutil.AssertProtoJSONEqual(t, `[
			`+routeString("path", "/.pomerium/jwt", true)+`,
			`+routeString("path", "/ping", false)+`,
			`+routeString("path", "/healthz", false)+`,
			`+routeString("path", "/.pomerium/admin", true)+`,
			`+routeString("prefix", "/.pomerium/admin/", true)+`,
			`+routeString("path", "/.pomerium", false)+`,
			`+routeString("prefix", "/.pomerium/", false)+`,
			`+routeString("path", "/.well-known/pomerium", false)+`,
			`+routeString("prefix", "/.well-known/pomerium/", false)+`,
			`+routeString("path", "/robots.txt", false)+`
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
				To:                               config.StringSlice{"https://to.example.com"},
				AllowPublicUnauthenticatedAccess: true,
			}},
		}
		_ = options.Policies[0].Validate()
		routes := buildPomeriumHTTPRoutes(options, "from.example.com")

		testutil.AssertProtoJSONEqual(t, `[
			`+routeString("path", "/.pomerium/jwt", true)+`,
			`+routeString("path", "/ping", false)+`,
			`+routeString("path", "/healthz", false)+`,
			`+routeString("path", "/.pomerium/admin", true)+`,
			`+routeString("prefix", "/.pomerium/admin/", true)+`,
			`+routeString("path", "/.pomerium", false)+`,
			`+routeString("prefix", "/.pomerium/", false)+`,
			`+routeString("path", "/.well-known/pomerium", false)+`,
			`+routeString("prefix", "/.well-known/pomerium/", false)+`
		]`, routes)
	})
}

func Test_buildControlPlanePathRoute(t *testing.T) {
	route := buildControlPlanePathRoute("/hello/world", false)
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
	route := buildControlPlanePrefixRoute("/hello/world/", false)
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
							"remove_impersonate_headers": false,
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
							"remove_impersonate_headers": false,
							"remove_pomerium_authorization": true,
							"remove_pomerium_cookie": "pomerium"
						}
					}
				},
				"route": {
					"autoHostRewrite": false,
					"cluster": "policy-2",
					"idleTimeout": "0s",
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
							"remove_impersonate_headers": false,
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
							"remove_impersonate_headers": false,
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
							"remove_impersonate_headers": false,
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
							"remove_impersonate_headers": false,
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
							"remove_impersonate_headers": false,
							"remove_pomerium_authorization": true,
							"remove_pomerium_cookie": "pomerium"
						}
					}
				},
				"route": {
					"autoHostRewrite": false,
					"cluster": "policy-7",
					"idleTimeout": "0s",
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
							"remove_impersonate_headers": false,
							"remove_pomerium_authorization": true,
							"remove_pomerium_cookie": "pomerium"
						}
					}
				},
				"route": {
					"autoHostRewrite": false,
					"cluster": "policy-8",
					"idleTimeout": "0s",
					"timeout": "10s",
					"upgradeConfigs": [
						{ "enabled": true, "upgradeType": "websocket"},
						{ "enabled": false, "upgradeType": "spdy/3.1"}
					]
				}
			}
		]
	`, routes)

	t.Run("tcp", func(t *testing.T) {
		routes = buildPolicyRoutes(&config.Options{
			CookieName:             "pomerium",
			DefaultUpstreamTimeout: time.Second * 3,
			Policies: []config.Policy{
				{
					Source:              &config.StringURL{URL: mustParseURL("tcp+https://example.com:22")},
					PassIdentityHeaders: true,
				},
				{
					Source:              &config.StringURL{URL: mustParseURL("tcp+https://example.com:22")},
					PassIdentityHeaders: true,
					UpstreamTimeout:     time.Second * 10,
				},
			},
		}, "example.com:22")

		testutil.AssertProtoJSONEqual(t, `
		[
			{
				"name": "policy-0",
				"match": {
					"connectMatcher": {}
				},
				"metadata": {
					"filterMetadata": {
						"envoy.filters.http.lua": {
							"remove_impersonate_headers": false,
							"remove_pomerium_authorization": true,
							"remove_pomerium_cookie": "pomerium"
						}
					}
				},
				"route": {
					"autoHostRewrite": true,
					"cluster": "policy-9",
					"idleTimeout": "0s",
					"timeout": "0s",
					"upgradeConfigs": [
						{ "enabled": false, "upgradeType": "websocket"},
						{ "enabled": false, "upgradeType": "spdy/3.1"},
						{ "enabled": true, "upgradeType": "CONNECT", "connectConfig": {} }
					]
				}
			},
			{
				"name": "policy-1",
				"match": {
					"connectMatcher": {}
				},
				"metadata": {
					"filterMetadata": {
						"envoy.filters.http.lua": {
							"remove_impersonate_headers": false,
							"remove_pomerium_authorization": true,
							"remove_pomerium_cookie": "pomerium"
						}
					}
				},
				"route": {
					"autoHostRewrite": true,
					"cluster": "policy-10",
					"idleTimeout": "0s",
					"timeout": "10s",
					"upgradeConfigs": [
						{ "enabled": false, "upgradeType": "websocket"},
						{ "enabled": false, "upgradeType": "spdy/3.1"},
						{ "enabled": true, "upgradeType": "CONNECT", "connectConfig": {} }
					]
				}
			}
		]
	`, routes)
	})
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
							"remove_impersonate_headers": false,
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

func Test_buildPolicyRoutesRewrite(t *testing.T) {
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
				Destinations:        mustParseURLs("https://foo.example.com/bar"),
				PassIdentityHeaders: true,
			},
			{
				Source:              &config.StringURL{URL: mustParseURL("https://example.com")},
				Destinations:        mustParseURLs("https://foo.example.com/bar"),
				PassIdentityHeaders: true,
				PrefixRewrite:       "/foo",
			},
			{
				Source:                   &config.StringURL{URL: mustParseURL("https://example.com")},
				Destinations:             mustParseURLs("https://foo.example.com/bar"),
				PassIdentityHeaders:      true,
				RegexRewritePattern:      "^/service/([^/]+)(/.*)$",
				RegexRewriteSubstitution: "\\2/instance/\\1",
			},
			{
				Source:              &config.StringURL{URL: mustParseURL("https://example.com")},
				Destinations:        mustParseURLs("https://foo.example.com/bar"),
				PassIdentityHeaders: true,
				HostRewrite:         "literal.example.com",
			},
			{
				Source:              &config.StringURL{URL: mustParseURL("https://example.com")},
				Destinations:        mustParseURLs("https://foo.example.com/bar"),
				PassIdentityHeaders: true,
				HostRewriteHeader:   "HOST_HEADER",
			},
			{
				Source:                           &config.StringURL{URL: mustParseURL("https://example.com")},
				Destinations:                     mustParseURLs("https://foo.example.com/bar"),
				PassIdentityHeaders:              true,
				HostPathRegexRewritePattern:      "^/(.+)/.+$",
				HostPathRegexRewriteSubstitution: "\\1",
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
							"remove_impersonate_headers": false,
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
			},
			{
				"name": "policy-1",
				"match": {
					"prefix": "/"
				},
				"metadata": {
					"filterMetadata": {
						"envoy.filters.http.lua": {
							"remove_impersonate_headers": false,
							"remove_pomerium_authorization": true,
							"remove_pomerium_cookie": "pomerium"
						}
					}
				},
				"route": {
					"autoHostRewrite": true,
					"prefixRewrite": "/foo",
					"cluster": "policy-2",
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
					"prefix": "/"
				},
				"metadata": {
					"filterMetadata": {
						"envoy.filters.http.lua": {
							"remove_impersonate_headers": false,
							"remove_pomerium_authorization": true,
							"remove_pomerium_cookie": "pomerium"
						}
					}
				},
				"route": {
					"autoHostRewrite": true,
					"regexRewrite": {
						"pattern": {
							"googleRe2": {},
							"regex": "^/service/([^/]+)(/.*)$"
						},
						"substitution": "\\2/instance/\\1"
					},
					"cluster": "policy-3",
					"timeout": "3s",
					"upgradeConfigs": [
						{ "enabled": false, "upgradeType": "websocket"},
						{ "enabled": false, "upgradeType": "spdy/3.1"}
					]
				}
			},
			{
				"name": "policy-3",
				"match": {
					"prefix": "/"
				},
				"metadata": {
					"filterMetadata": {
						"envoy.filters.http.lua": {
							"remove_impersonate_headers": false,
							"remove_pomerium_authorization": true,
							"remove_pomerium_cookie": "pomerium"
						}
					}
				},
				"route": {
					"hostRewriteLiteral": "literal.example.com",
					"prefixRewrite": "/bar",
					"cluster": "policy-4",
					"timeout": "3s",
					"upgradeConfigs": [
						{ "enabled": false, "upgradeType": "websocket"},
						{ "enabled": false, "upgradeType": "spdy/3.1"}
					]
				}
			},
			{
				"name": "policy-4",
				"match": {
					"prefix": "/"
				},
				"metadata": {
					"filterMetadata": {
						"envoy.filters.http.lua": {
							"remove_impersonate_headers": false,
							"remove_pomerium_authorization": true,
							"remove_pomerium_cookie": "pomerium"
						}
					}
				},
				"route": {
					"hostRewriteHeader": "HOST_HEADER",
					"prefixRewrite": "/bar",
					"cluster": "policy-5",
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
					"prefix": "/"
				},
				"metadata": {
					"filterMetadata": {
						"envoy.filters.http.lua": {
							"remove_impersonate_headers": false,
							"remove_pomerium_authorization": true,
							"remove_pomerium_cookie": "pomerium"
						}
					}
				},
				"route": {
					"hostRewritePathRegex": {
						"pattern": {
							"googleRe2": {},
							"regex": "^/(.+)/.+$"
						},
						"substitution": "\\1"
					},
					"prefixRewrite": "/bar",
					"cluster": "policy-6",
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

func Test_buildPolicyRouteRedirectAction(t *testing.T) {
	t.Run("HTTPSRedirect", func(t *testing.T) {
		action := buildPolicyRouteRedirectAction(&config.PolicyRedirect{
			HTTPSRedirect: proto.Bool(true),
		})
		assert.Equal(t, &envoy_config_route_v3.RedirectAction{
			SchemeRewriteSpecifier: &envoy_config_route_v3.RedirectAction_HttpsRedirect{
				HttpsRedirect: true,
			},
		}, action)

		action = buildPolicyRouteRedirectAction(&config.PolicyRedirect{
			HTTPSRedirect: proto.Bool(false),
		})
		assert.Equal(t, &envoy_config_route_v3.RedirectAction{
			SchemeRewriteSpecifier: &envoy_config_route_v3.RedirectAction_HttpsRedirect{
				HttpsRedirect: false,
			},
		}, action)
	})
	t.Run("SchemeRedirect", func(t *testing.T) {
		action := buildPolicyRouteRedirectAction(&config.PolicyRedirect{
			SchemeRedirect: proto.String("https"),
		})
		assert.Equal(t, &envoy_config_route_v3.RedirectAction{
			SchemeRewriteSpecifier: &envoy_config_route_v3.RedirectAction_SchemeRedirect{
				SchemeRedirect: "https",
			},
		}, action)
	})
	t.Run("HostRedirect", func(t *testing.T) {
		action := buildPolicyRouteRedirectAction(&config.PolicyRedirect{
			HostRedirect: proto.String("HOST"),
		})
		assert.Equal(t, &envoy_config_route_v3.RedirectAction{
			HostRedirect: "HOST",
		}, action)
	})
	t.Run("PortRedirect", func(t *testing.T) {
		action := buildPolicyRouteRedirectAction(&config.PolicyRedirect{
			PortRedirect: proto.Uint32(1234),
		})
		assert.Equal(t, &envoy_config_route_v3.RedirectAction{
			PortRedirect: 1234,
		}, action)
	})
	t.Run("PathRedirect", func(t *testing.T) {
		action := buildPolicyRouteRedirectAction(&config.PolicyRedirect{
			PathRedirect: proto.String("PATH"),
		})
		assert.Equal(t, &envoy_config_route_v3.RedirectAction{
			PathRewriteSpecifier: &envoy_config_route_v3.RedirectAction_PathRedirect{
				PathRedirect: "PATH",
			},
		}, action)
	})
	t.Run("PrefixRewrite", func(t *testing.T) {
		action := buildPolicyRouteRedirectAction(&config.PolicyRedirect{
			PrefixRewrite: proto.String("PREFIX_REWRITE"),
		})
		assert.Equal(t, &envoy_config_route_v3.RedirectAction{
			PathRewriteSpecifier: &envoy_config_route_v3.RedirectAction_PrefixRewrite{
				PrefixRewrite: "PREFIX_REWRITE",
			},
		}, action)
	})
	t.Run("ResponseCode", func(t *testing.T) {
		action := buildPolicyRouteRedirectAction(&config.PolicyRedirect{
			ResponseCode: proto.Int32(301),
		})
		assert.Equal(t, &envoy_config_route_v3.RedirectAction{
			ResponseCode: 301,
		}, action)
	})
	t.Run("StripQuery", func(t *testing.T) {
		action := buildPolicyRouteRedirectAction(&config.PolicyRedirect{
			StripQuery: proto.Bool(true),
		})
		assert.Equal(t, &envoy_config_route_v3.RedirectAction{
			StripQuery: true,
		}, action)
	})
}
