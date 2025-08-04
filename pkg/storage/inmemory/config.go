package inmemory

type config struct {
	degree int
}

// An Option customizes the in-memory backend.
type Option func(cfg *config)

func getConfig(options ...Option) *config {
	cfg := &config{
		degree: 16,
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
