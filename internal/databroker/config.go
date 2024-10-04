package databroker

import (
	"time"
)

var (
	// DefaultStorageType is the default storage type that Server use
	DefaultStorageType = "memory"
	// DefaultRegistryTTL is the default registry time to live.
	DefaultRegistryTTL = time.Minute
)

type serverConfig struct {
	storageType             string
	storageConnectionString string
	registryTTL             time.Duration
}

func newServerConfig(options ...ServerOption) *serverConfig {
	cfg := new(serverConfig)
	WithStorageType(DefaultStorageType)(cfg)
	WithRegistryTTL(DefaultRegistryTTL)(cfg)
	for _, option := range options {
		option(cfg)
	}
	return cfg
}

// A ServerOption customizes the server.
type ServerOption func(*serverConfig)

// WithRegistryTTL sets the registry time to live in the config.
func WithRegistryTTL(ttl time.Duration) ServerOption {
	return func(cfg *serverConfig) {
		cfg.registryTTL = ttl
	}
}

// WithStorageType sets the storage type.
func WithStorageType(typ string) ServerOption {
	return func(cfg *serverConfig) {
		cfg.storageType = typ
	}
}

// WithStorageConnectionString sets the DSN for storage.
func WithStorageConnectionString(connStr string) ServerOption {
	return func(cfg *serverConfig) {
		cfg.storageConnectionString = connStr
	}
}
