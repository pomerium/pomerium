package analytics

import "time"

var (
	// DefaultInitialDelay is the default initial delay before reporting analytics.
	DefaultInitialDelay = 5 * time.Minute
	// DefaultReportingInterval is the default reporting interval.
	DefaultReportingInterval = 12 * time.Hour
)

type reporterConfig struct {
	initialDelay      time.Duration
	reportingInterval time.Duration
}

// A ReporterOption customizes the reporter config.
type ReporterOption func(cfg *reporterConfig)

// WithInitialDelay sets the initial delay in the config.
func WithInitialDelay(initialDelay time.Duration) ReporterOption {
	return func(cfg *reporterConfig) {
		cfg.initialDelay = initialDelay
	}
}

// WithReportingInterval sets the reporting interval in the config.
func WithReportingInterval(reportingInterval time.Duration) ReporterOption {
	return func(cfg *reporterConfig) {
		cfg.reportingInterval = reportingInterval
	}
}

func getReporterConfig(options ...ReporterOption) *reporterConfig {
	cfg := new(reporterConfig)
	WithInitialDelay(DefaultInitialDelay)(cfg)
	WithReportingInterval(DefaultReportingInterval)(cfg)
	for _, option := range options {
		option(cfg)
	}
	return cfg
}
