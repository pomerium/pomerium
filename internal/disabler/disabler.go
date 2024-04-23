// package disabler contains a component that can be enabled and disabled dynamically
package disabler

import (
	"context"
	"errors"

	"github.com/pomerium/pomerium/internal/log"
)

var errDisabled = errors.New("disabled")

type Handler interface {
	RunEnabled(ctx context.Context) error
}

type Disabler interface {
	Run(ctx context.Context) error
	Enable()
	Disable()
}

type disabler struct {
	name            string
	handler         Handler
	onChangeEnabled chan bool
}

// New creates a new Disabler. When the Disabler is enabled, the Handler's
// RunEnabled will be called. If the Disabler is subsequently disabled the
// context passed to RunEnabled will be canceled. If the Disabler is subseqently
// enabled, RunEnabled will be started again.
func New(name string, handler Handler, enabled bool) Disabler {
	d := disabler{name: name, handler: handler, onChangeEnabled: make(chan bool, 1)}
	d.change(enabled)
	return d
}

func (d disabler) Run(ctx context.Context) error {
	for {
		// listen for a transition to enabled
		var enabled bool
		select {
		case <-ctx.Done():
			return ctx.Err()
		case enabled = <-d.onChangeEnabled:
		}
		if !enabled {
			// wait until we're enabled
			continue
		}

		log.Ctx(ctx).Info().Msgf("enabled %s", d.name)
		err := d.runEnabledOnce(ctx)
		if errors.Is(err, errDisabled) {
			log.Ctx(ctx).Info().Msgf("disabled %s", d.name)
			continue
		}

		// for any non-"disabled" error, we return it
		return err
	}
}

func (d disabler) runEnabledOnce(ctx context.Context) error {
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(context.Canceled) // ensure we cancel the context if we exit early

	// start a background goroutine that will listen for a transition to disabled
	go func() {
		for {
			var enabled bool
			select {
			case <-ctx.Done():
				return
			case enabled = <-d.onChangeEnabled:
			}
			if enabled {
				continue
			}
			cancel(errDisabled)
			return
		}
	}()

	// run the handler
	return d.handler.RunEnabled(ctx)
}

func (d disabler) Enable() {
	d.change(true)
}

func (d disabler) Disable() {
	d.change(false)
}

func (d disabler) change(enabled bool) {
	for {
		select {
		case d.onChangeEnabled <- enabled:
			return
		default:
		}

		select {
		case <-d.onChangeEnabled:
		default:
		}
	}
}
