package checkrequest

import (
	"net/url"
	"testing"

	envoy_service_auth_v3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/stretchr/testify/assert"
)

func TestGetURL(t *testing.T) {
	req := &envoy_service_auth_v3.CheckRequest{
		Attributes: &envoy_service_auth_v3.AttributeContext{
			Request: &envoy_service_auth_v3.AttributeContext_Request{
				Http: &envoy_service_auth_v3.AttributeContext_HttpRequest{
					Host:    "example.com:80",
					Path:    "/some/path?a=b",
					Scheme:  "http",
					Method:  "GET",
					Headers: map[string]string{"X-Request-Id": "CHECK-REQUEST-ID"},
				},
			},
		},
	}

	assert.Equal(t, url.URL{
		Scheme:   "http",
		Host:     "example.com",
		Path:     "/some/path",
		RawPath:  "/some/path",
		RawQuery: "a=b",
	}, GetURL(req))
}

func TestGetHeaders(t *testing.T) {
	req := &envoy_service_auth_v3.CheckRequest{
		Attributes: &envoy_service_auth_v3.AttributeContext{
			Request: &envoy_service_auth_v3.AttributeContext_Request{
				Http: &envoy_service_auth_v3.AttributeContext_HttpRequest{
					Headers: map[string]string{
						"content-type": "application/www-x-form-urlencoded",
						"x-request-id": "CHECK-REQUEST-ID",
						":authority":   "example.com",
					},
				},
			},
		},
	}

	assert.Equal(t, map[string]string{
		"Content-Type": "application/www-x-form-urlencoded",
		"X-Request-Id": "CHECK-REQUEST-ID",
		":authority":   "example.com",
	}, GetHeaders(req))
}
