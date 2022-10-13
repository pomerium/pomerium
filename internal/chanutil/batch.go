package chanutil

import "time"

const (
	defaultBatchMaxSize = 1024
	defaultBatchMaxWait = time.Millisecond * 300
)

type batchConfig struct {
	maxSize int
	maxWait time.Duration
}

// A BatchOption customizes a batch operation.
type BatchOption func(cfg *batchConfig)

// WithBatchMaxSize sets the maximum batch size for a Batch operation.
func WithBatchMaxSize(maxSize int) BatchOption {
	return func(cfg *batchConfig) {
		cfg.maxSize = maxSize
	}
}

// WithBatchMaxWait sets the maximum wait duration for a Batch operation.
func WithBatchMaxWait(maxWait time.Duration) BatchOption {
	return func(cfg *batchConfig) {
		cfg.maxWait = maxWait
	}
}

// Batch returns a new channel that consumes all the items from `in` and batches them together.
func Batch[T any](in <-chan T, options ...BatchOption) <-chan []T {
	cfg := new(batchConfig)
	WithBatchMaxSize(defaultBatchMaxSize)(cfg)
	WithBatchMaxWait(defaultBatchMaxWait)(cfg)
	for _, option := range options {
		option(cfg)
	}

	out := make(chan []T)
	go func() {
		var buf []T
		var timer <-chan time.Time
		for {
			if in == nil && timer == nil {
				close(out)
				return
			}

			select {
			case item, ok := <-in:
				if !ok {
					in = nil
					timer = time.After(0)
					continue
				}
				buf = append(buf, item)
				if timer == nil {
					timer = time.After(cfg.maxWait)
				}
			case <-timer:
				timer = nil
				for len(buf) > 0 {
					batch := buf
					if len(batch) > cfg.maxSize {
						batch = batch[:cfg.maxSize]
					}
					buf = buf[len(batch):]
					out <- batch
				}
			}
		}
	}()
	return out
}
