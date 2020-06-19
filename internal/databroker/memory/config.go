package memory

import "time"

var (
	// DefaultDeletePermanentlyAfter is the default amount of time to wait before deleting
	// a record permanently.
	DefaultDeletePermanentlyAfter = time.Hour
	// DefaultBTreeDegree is the default number of items to store in each node of the BTree.
	DefaultBTreeDegree = 8
)

type serverConfig struct {
	deletePermanentlyAfter time.Duration
	btreeDegree            int
}

func newServerConfig(options ...ServerOption) *serverConfig {
	cfg := new(serverConfig)
	WithDeletePermanentlyAfter(DefaultDeletePermanentlyAfter)(cfg)
	WithBTreeDegree(DefaultBTreeDegree)(cfg)
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
