package envoyconfig

import (
	"strconv"

	envoy_extensions_filters_http_ext_authz_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_authz/v3"
	"github.com/golang/protobuf/ptypes/any"
)

// PerFilterConfigExtAuthzName is the name of the ext authz filter to apply config to
const PerFilterConfigExtAuthzName = "envoy.filters.http.ext_authz"

// PerFilterConfigExtAuthzContextExtensions returns a per-filter config for ext authz that disables ext-authz.
func PerFilterConfigExtAuthzContextExtensions(authzContextExtensions map[string]string) *any.Any {
	return marshalAny(&envoy_extensions_filters_http_ext_authz_v3.ExtAuthzPerRoute{
		Override: &envoy_extensions_filters_http_ext_authz_v3.ExtAuthzPerRoute_CheckSettings{
			CheckSettings: &envoy_extensions_filters_http_ext_authz_v3.CheckSettings{
				ContextExtensions: authzContextExtensions,
			},
		},
	})
}

// PerFilterConfigExtAuthzDisabled returns a per-filter config for ext authz that disables ext-authz.
func PerFilterConfigExtAuthzDisabled() *any.Any {
	return marshalAny(&envoy_extensions_filters_http_ext_authz_v3.ExtAuthzPerRoute{
		Override: &envoy_extensions_filters_http_ext_authz_v3.ExtAuthzPerRoute_Disabled{
			Disabled: true,
		},
	})
}

// MakeExtAuthzContextExtensions makes the ext authz context extensions.
func MakeExtAuthzContextExtensions(internal bool, routeID uint64) map[string]string {
	return map[string]string{
		"internal": strconv.FormatBool(internal),
		"route_id": strconv.FormatUint(routeID, 10),
	}
}

// ExtAuthzContextExtensionsIsInternal returns true if the context extensions indicates the route is internal.
func ExtAuthzContextExtensionsIsInternal(extAuthzContextExtensions map[string]string) bool {
	return extAuthzContextExtensions != nil && extAuthzContextExtensions["internal"] == "true"
}

// ExtAuthzContextExtensionsRouteID returns the route id for the context extensions.
func ExtAuthzContextExtensionsRouteID(extAuthzContextExtensions map[string]string) uint64 {
	if extAuthzContextExtensions == nil {
		return 0
	}
	routeID, _ := strconv.ParseUint(extAuthzContextExtensions["route_id"], 10, 64)
	return routeID
}
