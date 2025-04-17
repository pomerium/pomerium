// Package checkrequest contains helper functions for working with Envoy
// ext_authz CheckRequest messages.
package checkrequest

import (
	"net/url"
	"strings"

	envoy_service_auth_v3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"

	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/urlutil"
)

// GetURL converts the request URL from an ext_authz CheckRequest to a [url.URL].
func GetURL(req *envoy_service_auth_v3.CheckRequest) url.URL {
	h := req.GetAttributes().GetRequest().GetHttp()
	u := url.URL{
		Scheme: h.GetScheme(),
		Host:   h.GetHost(),
	}
	u.Host = urlutil.GetDomainsForURL(&u, false)[0]
	// envoy sends the query string as part of the path
	path := h.GetPath()
	if idx := strings.Index(path, "?"); idx != -1 {
		u.RawPath, u.RawQuery = path[:idx], path[idx+1:]
		u.RawQuery = u.Query().Encode()
	} else {
		u.RawPath = path
	}
	u.Path, _ = url.PathUnescape(u.RawPath)
	return u
}

// GetHeaders returns the HTTP headers from an ext_authz CheckRequest, canonicalizing
// the header keys.
func GetHeaders(req *envoy_service_auth_v3.CheckRequest) map[string]string {
	hdrs := make(map[string]string)
	ch := req.GetAttributes().GetRequest().GetHttp().GetHeaders()
	for k, v := range ch {
		hdrs[httputil.CanonicalHeaderKey(k)] = v
	}
	return hdrs
}
