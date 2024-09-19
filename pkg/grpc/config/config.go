// Package config contains protobuf definitions for config.
package config

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

func (x *Config) GetId() string { //nolint
	return x.Name
}
