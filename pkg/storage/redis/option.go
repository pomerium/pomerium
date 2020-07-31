package redis

import "crypto/tls"

// Option customizes a DB.
type Option func(*DB)

// WithTLSConfig sets the tls.Config which DB uses.
func WithTLSConfig(tlsConfig *tls.Config) Option {
	return func(db *DB) {
		db.tlsConfig = tlsConfig
	}
}
