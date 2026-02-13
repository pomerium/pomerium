package blob

func WithInMemory() Option {
	return func(o *Options) {
		o.inMem = true
	}
}
