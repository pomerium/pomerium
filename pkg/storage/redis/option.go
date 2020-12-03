package redis

import (
	"crypto/tls"
)

type dbConfig struct {
	tls        *tls.Config
	recordType string
}

// Option customizes a DB.
type Option func(*dbConfig)

// WithRecordType sets the record type in the config.
func WithRecordType(recordType string) Option {
	return func(cfg *dbConfig) {
		cfg.recordType = recordType
	}
}

// WithTLSConfig sets the tls.Config which DB uses.
func WithTLSConfig(tlsConfig *tls.Config) Option {
	return func(cfg *dbConfig) {
		cfg.tls = tlsConfig
	}
}

func getConfig(options ...Option) *dbConfig {
	cfg := new(dbConfig)
	for _, o := range options {
		o(cfg)
	}
	return cfg
}
