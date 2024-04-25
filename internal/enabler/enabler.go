// package enabler contains a component that can be enabled and disabled dynamically
package enabler

import (
	"context"
	"errors"
	"sync"

	"github.com/pomerium/pomerium/internal/log"
)

var errCauseEnabler = errors.New("enabler")

// A Handler is a component with a RunEnabled function.
type Handler interface {
	RunEnabled(ctx context.Context) error
}

// HandlerFunc is a function run by the enabler.
type HandlerFunc func(ctx context.Context) error

func (f HandlerFunc) RunEnabled(ctx context.Context) error {
	return f(ctx)
}

// An Enabler enables or disables a component dynamically.
// When the Enabler is enabled, the Handler's RunEnabled will be called.
// If the Enabler is subsequently disabled the context passed to RunEnabled will be canceled.
// If the Enabler is subseqently enabled again, RunEnabled will be called again.
// Handlers should obey the context lifetime and be tolerant of RunEnabled
// being called multiple times. (not concurrently)
type Enabler interface {
	Run(ctx context.Context) error
	Enable()
	Disable()
}

type enabler struct {
	name    string
	handler Handler

	mu      sync.Mutex
	cancel  context.CancelCauseFunc
	enabled bool
}

// New creates a new Enabler.
func New(name string, handler Handler, enabled bool) Enabler {
	d := &enabler{
		name:    name,
		handler: handler,
		enabled: enabled,
		cancel:  func(_ error) {},
	}
	return d
}

// Run calls RunEnabled if enabled, otherwise it waits until enabled.
func (d *enabler) Run(ctx context.Context) error {
	for {
		err := d.runOnce(ctx)
		if errors.Is(err, errCauseEnabler) {
			continue
		}
		return err
	}
}

func (d *enabler) runOnce(ctx context.Context) error {
	d.mu.Lock()
	enabled := d.enabled
	ctx, d.cancel = context.WithCancelCause(ctx)
	d.mu.Unlock()

	if enabled {
		log.Ctx(ctx).Info().Msgf("enabled %s", d.name)
		err := d.handler.RunEnabled(ctx)
		// if RunEnabled stopped because we canceled the context
		if errors.Is(err, context.Canceled) && errors.Is(context.Cause(ctx), errCauseEnabler) {
			log.Ctx(ctx).Info().Msgf("disabled %s", d.name)
			return errCauseEnabler
		}
		return err
	}

	// wait for a transition from disabled -> enabled
	<-ctx.Done()
	return context.Cause(ctx)
}

func (d *enabler) Enable() {
	d.mu.Lock()
	if !d.enabled {
		d.enabled = true
		d.cancel(errCauseEnabler)
	}
	d.mu.Unlock()
}

func (d *enabler) Disable() {
	d.mu.Lock()
	if d.enabled {
		d.enabled = false
		d.cancel(errCauseEnabler)
	}
	d.mu.Unlock()
}
