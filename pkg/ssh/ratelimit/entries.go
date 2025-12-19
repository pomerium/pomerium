// Contains dynamic access log field values and rate limit entry key decision
// https://www.envoyproxy.io/docs/envoy/latest/configuration/observability/access_log/usage#config-access-log
package ratelimit

// Dynamic fields
const (
	// DownstreamDirectRemoteAddressWithoutPort Direct remote address of the downstream connection, without any port component.
	// IP addresses are the only address type with a port component.
	// This is always the physical remote address of the peer even if the downstream remote address has been inferred from Proxy Protocol filter or x-forwarded-for.
	DownstreamDirectRemoteAddressWithoutPort = "%DOWNSTREAM_DIRECT_REMOTE_ADDRESS_WITHOUT_PORT%"
)

const (
	EntryDownstreamIP = "downstream_ip"
)
