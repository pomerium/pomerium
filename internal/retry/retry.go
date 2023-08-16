// Package retry provides a retry loop with exponential back-off
// while watching arbitrary signal channels for side effects.
package retry

import (
	"context"
	"fmt"
	"reflect"
	"time"
)

// Retry retries a function (with exponential back-off) until it succeeds.
// It additionally watches arbitrary channels and calls the handler function when a value is received.
// Handler functions are also retried with exponential back-off.
// If a terminal error is returned from the handler function, the retry loop is aborted.
// If the context is canceled, the retry loop is aborted.
func Retry(
	ctx context.Context,
	name string,
	fn func(context.Context) error,
	opts ...Option,
) error {
	watches, backoff := newConfig(opts...)
	ticker := time.NewTicker(backoff.NextBackOff())
	defer ticker.Stop()

	s := makeSelect(ctx, watches, name, ticker.C, fn)

restart:
	for {
		err := fn(ctx)
		if err == nil {
			return nil
		}
		if IsTerminalError(err) {
			return err
		}

		backoff.Reset()
	backoff:
		for {
			ticker.Reset(backoff.NextBackOff())

			next, err := s.Exec(ctx)
			switch next {
			case nextRestart:
				continue restart
			case nextBackoff:
				continue backoff
			case nextExit:
				return err
			default:
				panic("unreachable")
			}
		}
	}
}

type selectCase struct {
	watches []watch
	cases   []reflect.SelectCase
}

func makeSelect(
	ctx context.Context,
	watches []watch,
	name string,
	ch <-chan time.Time,
	fn func(context.Context) error,
) *selectCase {
	watches = append(watches,
		watch{
			name: "context",
			fn: func(ctx context.Context) error {
				// unreachable, the context handler will never be called
				// as its channel can only be closed
				return ctx.Err()
			},
			ch: reflect.ValueOf(ctx.Done()),
		},
		watch{
			name: name,
			fn:   fn,
			ch:   reflect.ValueOf(ch),
			this: true,
		},
	)
	cases := make([]reflect.SelectCase, 0, len(watches))
	for _, w := range watches {
		cases = append(cases, reflect.SelectCase{
			Dir:  reflect.SelectRecv,
			Chan: w.ch,
		})
	}
	return &selectCase{
		watches: watches,
		cases:   cases,
	}
}

type next int

const (
	nextRestart next = iota // try again from the beginning
	nextBackoff             // backoff and try again
	nextExit                // exit
)

func (s *selectCase) Exec(ctx context.Context) (next, error) {
	chosen, _, ok := reflect.Select(s.cases)
	if !ok {
		return nextExit, fmt.Errorf("watch %s closed", s.watches[chosen].name)
	}

	w := s.watches[chosen]

	err := w.fn(ctx)
	if err != nil {
		return onError(w, err)
	}

	if !w.this {
		return nextRestart, nil
	}

	return nextExit, nil
}

func onError(w watch, err error) (next, error) {
	if IsTerminalError(err) {
		return nextExit, err
	}

	if w.this {
		return nextBackoff, fmt.Errorf("retry %s failed: %w", w.name, err)
	}

	panic("unreachable, as watches are wrapped in retries and may only return terminal errors")
}
