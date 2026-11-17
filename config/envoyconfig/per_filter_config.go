package envoyconfig

import (
	"math"
	"strconv"

	envoy_extensions_filters_http_ext_authz_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_authz/v3"
	"google.golang.org/protobuf/types/known/anypb"
)

// PerFilterConfigExtAuthzName is the name of the ext authz filter to apply config to
const PerFilterConfigExtAuthzName = "envoy.filters.http.ext_authz"

// PerFilterConfigExtProcName is the name of the ext_proc filter to apply config to
const PerFilterConfigExtProcName = "envoy.filters.http.ext_proc"

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
//
// Envoy only answers 413 itself when an oversized body arrives in several
// chunks; a body that arrives in one chunk is truncated to the buffer limit and
// sent to authorize. The buffer is one byte larger than mcpRequestBodyMaxBytes
// so authorize can tell those truncated bodies apart and reject them with 413.
func PerFilterConfigExtAuthzContextExtensionsWithBody(mcpRequestBodyMaxBytes uint32, authzContextExtensions map[string]string) *anypb.Any {
	maxRequestBytes := mcpRequestBodyMaxBytes
	if maxRequestBytes < math.MaxUint32 {
		maxRequestBytes++
	}
	return marshalAny(&envoy_extensions_filters_http_ext_authz_v3.ExtAuthzPerRoute{
		Override: &envoy_extensions_filters_http_ext_authz_v3.ExtAuthzPerRoute_CheckSettings{
			CheckSettings: &envoy_extensions_filters_http_ext_authz_v3.CheckSettings{
				ContextExtensions: authzContextExtensions,
				WithRequestBody: &envoy_extensions_filters_http_ext_authz_v3.BufferSettings{
					MaxRequestBytes:     maxRequestBytes,
					AllowPartialMessage: false,
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
func MakeExtAuthzContextExtensions(internal bool, routeID string, routeChecksum uint64) map[string]string {
	return map[string]string{
		"internal":       strconv.FormatBool(internal),
		"route_id":       routeID,
		"route_checksum": strconv.FormatUint(routeChecksum, 10),
	}
}

// ExtAuthzContextExtensionsIsInternal returns true if the context extensions indicates the route is internal.
func ExtAuthzContextExtensionsIsInternal(extAuthzContextExtensions map[string]string) bool {
	return extAuthzContextExtensions != nil && extAuthzContextExtensions["internal"] == "true"
}

// ExtAuthzContextExtensionsIsConsoleRoute returns true if the context extensions indicates the route is a console route.
func ExtAuthzContextExtensionsIsConsoleRoute(extAuthzContextExtensions map[string]string) bool {
	return extAuthzContextExtensions != nil && extAuthzContextExtensions["console"] == "true"
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
