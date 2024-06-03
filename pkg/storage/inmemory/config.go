package inmemory

import "time"

type config struct {
	degree int
	expiry time.Duration
	file   string
}

// An Option customizes the in-memory backend.
type Option func(cfg *config)

func getConfig(options ...Option) *config {
	cfg := &config{
		degree: 16,
		expiry: time.Hour,
		file:   "pomerium.db",
	}
	for _, option := range options {
		option(cfg)
	}
	return cfg
}

// WithBTreeDegree sets the btree degree of the changes btree.
func WithBTreeDegree(degree int) Option {
	return func(cfg *config) {
		cfg.degree = degree
	}
}

// WithExpiry sets the expiry for changes.
func WithExpiry(expiry time.Duration) Option {
	return func(cfg *config) {
		cfg.expiry = expiry
	}
}

func WithFile(file string) Option {
	return func(cfg *config) {
		cfg.file = file
	}
}
