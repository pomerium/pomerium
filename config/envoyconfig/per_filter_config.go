package envoyconfig

import (
	"strconv"

	envoy_extensions_filters_http_ext_authz_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_authz/v3"
	"google.golang.org/protobuf/types/known/anypb"
)

// PerFilterConfigExtAuthzName is the name of the ext authz filter to apply config to
const PerFilterConfigExtAuthzName = "envoy.filters.http.ext_authz"

// PerFilterConfigExtAuthzContextExtensions returns a per-filter config for ext authz that disables ext-authz.
func PerFilterConfigExtAuthzContextExtensions(authzContextExtensions map[string]string) *anypb.Any {
	return marshalAny(&envoy_extensions_filters_http_ext_authz_v3.ExtAuthzPerRoute{
		Override: &envoy_extensions_filters_http_ext_authz_v3.ExtAuthzPerRoute_CheckSettings{
			CheckSettings: &envoy_extensions_filters_http_ext_authz_v3.CheckSettings{
				ContextExtensions: authzContextExtensions,
			},
		},
	})
}

// PerFilterConfigExtAuthzContextExtensionsWithBody returns a per-filter config for ext authz that
// sets context extensions and includes the request body.
func PerFilterConfigExtAuthzContextExtensionsWithBody(mcpRequestBodyMaxBytes uint32, authzContextExtensions map[string]string) *anypb.Any {
	return marshalAny(&envoy_extensions_filters_http_ext_authz_v3.ExtAuthzPerRoute{
		Override: &envoy_extensions_filters_http_ext_authz_v3.ExtAuthzPerRoute_CheckSettings{
			CheckSettings: &envoy_extensions_filters_http_ext_authz_v3.CheckSettings{
				ContextExtensions: authzContextExtensions,
				WithRequestBody: &envoy_extensions_filters_http_ext_authz_v3.BufferSettings{
					MaxRequestBytes:     mcpRequestBodyMaxBytes,
					AllowPartialMessage: true,
				},
			},
		},
	})
}

// PerFilterConfigExtAuthzDisabled returns a per-filter config for ext authz that disables ext-authz.
func PerFilterConfigExtAuthzDisabled() *anypb.Any {
	return marshalAny(&envoy_extensions_filters_http_ext_authz_v3.ExtAuthzPerRoute{
		Override: &envoy_extensions_filters_http_ext_authz_v3.ExtAuthzPerRoute_Disabled{
			Disabled: true,
		},
	})
}

// MakeExtAuthzContextExtensions makes the ext authz context extensions.
func MakeExtAuthzContextExtensions(internal bool, routeID string, routeChecksum uint64, cluster string) map[string]string {
	return map[string]string{
		"internal":       strconv.FormatBool(internal),
		"route_id":       routeID,
		"route_checksum": strconv.FormatUint(routeChecksum, 10),
		"cluster":        cluster,
	}
}

// ExtAuthzContextExtensionsIsInternal returns true if the context extensions indicates the route is internal.
func ExtAuthzContextExtensionsIsInternal(extAuthzContextExtensions map[string]string) bool {
	return extAuthzContextExtensions != nil && extAuthzContextExtensions["internal"] == "true"
}

// ExtAuthzContextExtensionsRouteID returns the route id for the context extensions.
func ExtAuthzContextExtensionsRouteID(extAuthzContextExtensions map[string]string) string {
	if extAuthzContextExtensions == nil {
		return ""
	}
	return extAuthzContextExtensions["route_id"]
}

// ExtAuthzContextExtensionsRouteChecksum returns the route checksum for the context extensions.
func ExtAuthzContextExtensionsRouteChecksum(extAuthzContextExtensions map[string]string) uint64 {
	if extAuthzContextExtensions == nil {
		return 0
	}
	v, _ := strconv.ParseUint(extAuthzContextExtensions["route_checksum"], 10, 64)
	return v
}

// ExtAuthzContextExtensionsCluster returns the cluster name for the context extensions.
func ExtAuthzContextExtensionsCluster(extAuthzContextExtensions map[string]string) string {
	if extAuthzContextExtensions == nil {
		return ""
	}
	return extAuthzContextExtensions["cluster"]
}
