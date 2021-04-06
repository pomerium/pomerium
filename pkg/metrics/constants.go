// Package metrics declares metrics names and labels that pomerium exposes
// as constants that could be referred to from other projects
package metrics

// metrics
const (
	AutocertRenewalsTotal                 = "autocert_renewals_total"
	AutocertCertificatesTotal             = "autocert_certificates_total"
	AutocertCertificateNextExpiresSeconds = "autocert_certificate_next_expires_seconds"
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
	// ConfigDbVersion sets currently loaded databroker config version config_db_version{service="service",id="config_id"}
	ConfigDbVersion = "config_db_version"
	// ConfigDbVersionHelp
	ConfigDbVersionHelp = "databroker current config record version"
	// ConfigDbErrors sets number of errors while parsing current config that were tolerated
	ConfigDbErrors = "config_db_errors"
	// ConfigDbErrorsHelp
	ConfigDbErrorsHelp = "amount of errors observed while applying databroker config; -1 if validation failed and was rejected altogether"
)

// labels
const (
	InstallationIDLabel = "installation_id"
	ServiceLabel        = "service"
	ConfigLabel         = "config"
	VersionLabel        = "version"
	RevisionLabel       = "revision"
	GoVersionLabel      = "goversion"
	HostLabel           = "host"
)
