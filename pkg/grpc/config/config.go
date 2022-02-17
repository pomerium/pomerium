// Package config contains protobuf definitions for config.
package config

import "strings"

// IsSet returns true if one of the route redirect options has been chosen.
func (rr *RouteRedirect) IsSet() bool {
	if rr == nil {
		return false
	}

	return rr.StripQuery != nil ||
		rr.ResponseCode != nil ||
		rr.PrefixRewrite != nil ||
		rr.PathRedirect != nil ||
		rr.PortRedirect != nil ||
		rr.HostRedirect != nil ||
		rr.SchemeRedirect != nil ||
		rr.HttpsRedirect != nil
}

// Route_AuthorizationHeaderModeFromString returns the Route_AuthorizationHeaderMode from a string.
func Route_AuthorizationHeaderModeFromString(raw string) (Route_AuthorizationHeaderMode, bool) { //nolint
	mode, ok := Route_AuthorizationHeaderMode_value[strings.ToUpper(raw)]
	return Route_AuthorizationHeaderMode(mode), ok
}
