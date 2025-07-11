package telemetry

import "strings"

// ServiceName turns a pomerium service option into the appropriate external label for telemetry purposes
//
// Ex:
// service 'all' -> 'pomerium'
// service 'proxy' -> 'pomerium-proxy'
func ServiceName(service string) string {
	if strings.Count(service, ",") > 0 || service == "all" || service == "" {
		return "pomerium"
	}
	return "pomerium-" + service
}
