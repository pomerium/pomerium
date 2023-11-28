// Package errgrouputil contains methods for working with errgroup code.
package errgrouputil

import (
	"context"
	"runtime"

	"golang.org/x/sync/errgroup"

	"github.com/pomerium/pomerium/pkg/slices"
)

// BuilderFunc is a function that builds a value of type T
type BuilderFunc[T any] func(ctx context.Context) (*T, error)

// Build builds a slice of values of type T using the provided builders concurrently
// and returns the results and any errors.
func Build[T any](
	ctx context.Context,
	builders ...BuilderFunc[T],
) ([]*T, []error) {
	eg, ctx := errgroup.WithContext(ctx)
	eg.SetLimit(runtime.GOMAXPROCS(0)/2 + 1)

	results := make([]*T, len(builders))
	errors := make([]error, len(builders))

	fn := func(i int) func() error {
		return func() error {
			result, err := builders[i](ctx)
			if err != nil {
				errors[i] = err
				return nil
			}
			results[i] = result
			return nil
		}
	}

	for i := range builders {
		eg.Go(fn(i))
	}

	err := eg.Wait()
	if err != nil {
		return nil, []error{err} // not happening
	}

	return slices.Filter(results, func(t *T) bool {
			return t != nil
		}), slices.Filter(errors, func(err error) bool {
			return err != nil
		})
}
