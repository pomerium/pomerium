package telemetry

// ServiceName turns a pomerium service option into the appropriate external label for telemetry purposes
//
// Ex:
// service 'all' -> 'pomerium'
// service 'proxy' -> 'pomerium-proxy'
func ServiceName(service string) string {
	switch service {
	case "all", "":
		return "pomerium"
	default:
		return "pomerium-" + service
	}
}
