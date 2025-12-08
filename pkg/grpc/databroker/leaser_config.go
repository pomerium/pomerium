package databroker

type leaserConfig struct {
	errorHandler func(error)
}

// A LeaserOption customizes the leaser config.
type LeaserOption = func(cfg *leaserConfig)

// WithLeaserErrorHandler sets the error handler in the leaser config.
func WithLeaserErrorHandler(errorHandler func(error)) LeaserOption {
	return func(cfg *leaserConfig) {
		cfg.errorHandler = errorHandler
	}
}

func getLeaserConfig(options ...LeaserOption) *leaserConfig {
	cfg := new(leaserConfig)
	WithLeaserErrorHandler(func(_ error) {})(cfg)
	for _, option := range options {
		option(cfg)
	}
	return cfg
}
