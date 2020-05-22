package controlplane

import (
	"net/url"
	"testing"

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

func mustParseURL(str string) *url.URL {
	u, err := url.Parse(str)
	if err != nil {
		panic(err)
	}
	return u
}
