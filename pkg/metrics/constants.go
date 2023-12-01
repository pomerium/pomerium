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

	// IdentityManagerLastUserRefreshSuccessTimestamp is a timestamp of last user refresh
	IdentityManagerLastUserRefreshSuccessTimestamp = "identity_manager_last_user_refresh_success_timestamp"
	// IdentityManagerLastUserRefreshErrorTimestamp is a timestamp of last user refresh error
	IdentityManagerLastUserRefreshErrorTimestamp = "identity_manager_last_user_refresh_error_timestamp"
	// IdentityManagerLastUserRefreshError is a counter of last user refresh errors
	IdentityManagerLastUserRefreshError = "identity_manager_last_user_refresh_errors"
	// IdentityManagerLastUserRefreshSuccess is a counter of last user refresh success
	IdentityManagerLastUserRefreshSuccess = "identity_manager_last_user_refresh_success"

	// IdentityManagerLastUserGroupRefreshSuccessTimestamp is a timestamp of last user group refresh
	IdentityManagerLastUserGroupRefreshSuccessTimestamp = "identity_manager_last_user_group_refresh_success_timestamp"
	// IdentityManagerLastUserGroupRefreshErrorTimestamp is a timestamp of last user group refresh error
	IdentityManagerLastUserGroupRefreshErrorTimestamp = "identity_manager_last_user_group_refresh_error_timestamp"
	// IdentityManagerLastUserGroupRefreshError is a counter of last user group refresh errors
	IdentityManagerLastUserGroupRefreshError = "identity_manager_last_user_group_refresh_errors"
	// IdentityManagerLastUserGroupRefreshSuccess is a counter of last user group refresh success
	IdentityManagerLastUserGroupRefreshSuccess = "identity_manager_last_user_group_refresh_success"

	// IdentityManagerLastSessionRefreshSuccessTimestamp is a timestamp of last session refresh
	IdentityManagerLastSessionRefreshSuccessTimestamp = "identity_manager_last_session_refresh_success_timestamp"
	// IdentityManagerLastSessionRefreshErrorTimestamp is a timestamp of last session refresh error
	IdentityManagerLastSessionRefreshErrorTimestamp = "identity_manager_last_session_refresh_error_timestamp"
	// IdentityManagerLastSessionRefreshError is a counter of last session refresh errors
	IdentityManagerLastSessionRefreshError = "identity_manager_last_session_refresh_errors"
	// IdentityManagerLastSessionRefreshSuccess is a counter of last session refresh success
	IdentityManagerLastSessionRefreshSuccess = "identity_manager_last_session_refresh_success"

	// BuildInfo is a gauge that may be used to detect whether component is live, and also has version
	BuildInfo = "build_info"
	// PolicyCountTotal is total amount of routes currently configured
	PolicyCountTotal = "policy_count_total"
	// ConfigChecksumDecimal should only be used to compare config on a single node, it will be different in multi-node environment
	ConfigChecksumDecimal = "config_checksum_decimal"
	// ConfigDBVersion sets currently loaded databroker config version config_db_version{service="service",id="config_id"}
	ConfigDBVersion = "config_db_version"
	// ConfigDBVersionHelp is the help text for ConfigDBVersion.
	ConfigDBVersionHelp = "databroker current config record version"
	// ConfigDBErrors sets number of errors while parsing current config that were tolerated
	ConfigDBErrors = "config_db_errors"
	// ConfigDBErrorsHelp is the help text for ConfigDBErrors.
	ConfigDBErrorsHelp = "amount of errors observed while applying databroker config; -1 if validation failed and was rejected altogether"

	// PgxpoolAcquireCount is the cumulative count of successful acquires from
	// the current database connection pool.
	PgxpoolAcquireCount = "pgxpool_acquire_count"
	// PgxpoolAcquireDuration is the total duration of all successful acquires
	// from the current database connection pool.
	PgxpoolAcquireDurationSeconds = "pgxpool_acquire_duration_seconds"
	// PgxpoolAcquiredConns is the number of currently acquired connections in
	// the current database connection pool.
	PgxpoolAcquiredConns = "pgxpool_acquired_conns"
	// PgxpoolCanceledAcquireCount is the cumulative count of acquires from the
	// current database connection pool that were canceled by a context.
	PgxpoolCanceledAcquireCount = "pgxpool_canceled_acquire_count"
	// PgxpoolConstructingConns is the number of conns with construction in
	// progress in the current database connection pool.
	PgxpoolConstructingConns = "pgxpool_constructing_conns"
	// PgxpoolEmptyAcquireCount is the cumulative count of successful acquires
	// from the current database connection pool that waited for a resource to
	// be released or constructed because the pool was empty.
	PgxpoolEmptyAcquireCount = "pgxpool_empty_acquire_count"
	// PgxpoolIdleConns is the number of currently idle conns in the current
	// database connection pool.
	PgxpoolIdleConns = "pgxpool_idle_conns"
	// PgxpoolMaxConns is the maximum size of the current database connection
	// pool.
	PgxpoolMaxConns = "pgxpool_max_conns"
	// PgxpoolMaxIdleDestroyCount is the cumulative count of connections
	// destroyed by the current database connection pool because they exceeded
	// the MaxConnIdleTime.
	PgxpoolMaxIdleDestroyCount = "pgxpool_max_idle_destroy_count"
	// PgxpoolMaxLifetimeDestroyCount is the cumulative count of connections
	// destroyed by the current database connection pool because they exceeded
	// the MaxConnLifetime.
	PgxpoolMaxLifetimeDestroyCount = "pgxpool_max_lifetime_destroy_count"
	// PgxpoolNewConnsCount is the cumulative count of new connections opened
	// by the current database connection pool.
	PgxpoolNewConnsCount = "pgxpool_new_conns_count"
)

// labels
const (
	InstallationIDLabel = "installation_id"
	HostnameLabel       = "hostname"
	ServiceLabel        = "service"
	ConfigLabel         = "config"
	VersionLabel        = "version"
	EnvoyVersionLabel   = "envoy_version"
	RevisionLabel       = "revision"
	GoVersionLabel      = "goversion"
	HostLabel           = "host"
)
