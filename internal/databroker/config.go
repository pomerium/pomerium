package databroker

import "time"

var (
	// DefaultDeletePermanentlyAfter is the default amount of time to wait before deleting
	// a record permanently.
	DefaultDeletePermanentlyAfter = time.Hour
	// DefaultBTreeDegree is the default number of items to store in each node of the BTree.
	DefaultBTreeDegree = 8
	// DefaultStorageType is the default storage type that Server use
	DefaultStorageType = "memory"
)

type serverConfig struct {
	deletePermanentlyAfter time.Duration
	btreeDegree            int
	storageType            string
	storageDSN             string
}

func newServerConfig(options ...ServerOption) *serverConfig {
	cfg := new(serverConfig)
	WithDeletePermanentlyAfter(DefaultDeletePermanentlyAfter)(cfg)
	WithBTreeDegree(DefaultBTreeDegree)(cfg)
	WithStorageType(DefaultStorageType)(cfg)
	for _, option := range options {
		option(cfg)
	}
	return cfg
}

// A ServerOption customizes the server.
type ServerOption func(*serverConfig)

// WithBTreeDegree sets the number of items to store in each node of the BTree.
func WithBTreeDegree(degree int) ServerOption {
	return func(cfg *serverConfig) {
		cfg.btreeDegree = degree
	}
}

// WithDeletePermanentlyAfter sets the deletePermanentlyAfter duration.
// If a record is deleted via Delete, it will be permanently deleted after
// the given duration.
func WithDeletePermanentlyAfter(dur time.Duration) ServerOption {
	return func(cfg *serverConfig) {
		cfg.deletePermanentlyAfter = dur
	}
}

// WithStorageType sets the storage type.
func WithStorageType(typ string) ServerOption {
	return func(cfg *serverConfig) {
		cfg.storageType = typ
	}
}

// WithStorageConnectionString sets the DSN for storage.
func WithStorageConnectionString(dsn string) ServerOption {
	return func(cfg *serverConfig) {
		cfg.storageDSN = dsn
	}
}
