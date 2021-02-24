// Package metrics declares metrics names and labels that pomerium exposes
// as constants that could be referred to from other projects
package metrics

// metrics
const (
	// ConfigLastReloadTimestampSeconds is unix timestamp when configuration was last reloaded
	ConfigLastReloadTimestampSeconds = "config_last_reload_success_timestamp"
	// ConfigLastReloadSuccess is set to 1 if last configuration was successfully reloaded
	ConfigLastReloadSuccess = "config_last_reload_success"
	// IdentityManagerLastRefreshTimestamp is IdP sync timestamp
	IdentityManagerLastRefreshTimestamp = "identity_manager_last_refresh_timestamp"
	// BuildInfo is a gauge that may be used to detect whether component is live, and also has version
	BuildInfo = "build_info"
	// PolicyCountTotal is total amount of routes currently configured
	PolicyCountTotal = "policy_count_total"
	// ConfigChecksumDecimal should only be used to compare config on a single node, it will be different in multi-node environment
	ConfigChecksumDecimal = "config_checksum_decimal"
)

// labels
const (
	ServiceLabel   = "service"
	VersionLabel   = "version"
	RevisionLabel  = "revision"
	GoVersionLabel = "goversion"
	HostLabel      = "host"
)
