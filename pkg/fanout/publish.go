package fanout

import "context"

// Publish publishes a message to all currently registered subscribers
// if the fanout is closed, ErrStopped is returned
func (f *FanOut[T]) Publish(ctx context.Context, msg T) error {
	ctx, cancel := context.WithTimeout(ctx, f.cfg.publishTimeout)
	defer cancel()

	select {
	case <-ctx.Done():
		return context.Cause(ctx)
	case <-f.done:
		return ErrStopped
	case f.messages <- msg:
		return nil
	}
}
