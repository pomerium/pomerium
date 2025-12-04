package testenv

import (
	"context"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/testenv/values"
	"github.com/pomerium/pomerium/pkg/cmd/pomerium"
)

type envContextKeyType struct{}

var envContextKey envContextKeyType

func EnvFromContext(ctx context.Context) Environment {
	return ctx.Value(envContextKey).(Environment)
}

func ContextWithEnv(ctx context.Context, env Environment) context.Context {
	return context.WithValue(ctx, envContextKey, env)
}

// A Modifier is an object whose presence in the test affects the Pomerium
// configuration in some way. When the test environment is started, a
// [*config.Config] is constructed by calling each added Modifier in order.
//
// For additional details, see [Environment.Add] and [Environment.Start].
type Modifier interface {
	// Attach is called by an [Environment] (before Modify) to propagate the
	// environment's context.
	Attach(ctx context.Context)

	// Modify is called by an [Environment] to mutate its configuration in some
	// way required by this Modifier.
	Modify(cfg *config.Config)
}

// DefaultAttach should be embedded in types implementing [Modifier] to
// automatically obtain environment context details and caller information.
type DefaultAttach struct {
	env    Environment
	caller string
}

func (d *DefaultAttach) Env() Environment {
	d.CheckAttached()
	return d.env
}

func (d *DefaultAttach) Attach(ctx context.Context) {
	if d.env != nil {
		panic("internal test environment bug: Attach called twice")
	}
	d.env = EnvFromContext(ctx)
	if d.env == nil {
		panic("test bug: no environment in context")
	}
}

func (d *DefaultAttach) CheckAttached() {
	if d.env == nil {
		if d.caller != "" {
			panic("test bug: missing a call to Add for the object created at: " + d.caller)
		}
		panic("test bug: not attached (possibly missing a call to Add)")
	}
}

func (d *DefaultAttach) RecordCaller() {
	d.caller = getCaller(4)
}

func (d *DefaultAttach) Modify(*config.Config) {}

// Aggregate should be embedded in types implementing [Modifier] when the type
// contains other modifiers. Used as an alternative to [DefaultAttach].
// Embedding this struct will properly keep track of when constituent modifiers
// are added, for validation and caller detection.
//
// Aggregate implements a no-op Modify() by default, but this can be overridden
// to make additional modifications. The aggregate's Modify() is called first.
type Aggregate struct {
	env       Environment
	caller    string
	modifiers []Modifier
}

func (d *Aggregate) Add(mod Modifier) {
	if d.env != nil {
		if d.env.(*environment).GetState() == NotRunning {
			// If the test environment is running, adding to an aggregate is a no-op.
			// If the test environment has not been started yet, the aggregate is
			// being used like in the following example, which is incorrect:
			//
			// 	aggregate.Add(foo)
			//  env.Add(aggregate)
			//  aggregate.Add(bar)
			//  env.Start()
			//
			// It should instead be used like this:
			//
			// 	aggregate.Add(foo)
			//  aggregate.Add(bar)
			//  env.Add(aggregate)
			//  env.Start()
			panic("test bug: cannot modify an aggregate that has already been added")
		}
		return
	}
	d.modifiers = append(d.modifiers, mod)
}

func (d *Aggregate) Env() Environment {
	d.CheckAttached()
	return d.env
}

func (d *Aggregate) Attach(ctx context.Context) {
	if d.env != nil {
		panic("internal test environment bug: Attach called twice")
	}
	d.env = EnvFromContext(ctx)
	if d.env == nil {
		panic("test bug: no environment in context")
	}
	d.env.(*environment).t.Helper()
	for _, mod := range d.modifiers {
		d.env.Add(mod)
	}
}

func (d *Aggregate) Modify(*config.Config) {}

func (d *Aggregate) CheckAttached() {
	if d.env == nil {
		if d.caller != "" {
			panic("test bug: missing a call to Add for the object created at: " + d.caller)
		}
		panic("test bug: not attached (possibly missing a call to Add)")
	}
}

func (d *Aggregate) RecordCaller() {
	d.caller = getCaller(4)
}

type modifierFunc struct {
	fn  func(ctx context.Context, cfg *config.Config)
	ctx context.Context
}

// Attach implements Modifier.
func (f *modifierFunc) Attach(ctx context.Context) {
	f.ctx = ctx
}

func (f *modifierFunc) Modify(cfg *config.Config) {
	f.fn(f.ctx, cfg)
}

var _ Modifier = (*modifierFunc)(nil)

func ModifierFunc(fn func(ctx context.Context, cfg *config.Config)) Modifier {
	return &modifierFunc{fn: fn}
}

func NoopModifier() Modifier {
	return noopModifier{}
}

type noopModifier struct{}

// Attach implements Modifier.
func (n noopModifier) Attach(context.Context) {}

// Modify implements Modifier.
func (n noopModifier) Modify(*config.Config) {}

var _ Modifier = (noopModifier{})

type OptionConfigurator interface {
	Configure(options *pomerium.Options)
}

type optionConfiguratorFunc struct {
	option pomerium.Option
}

func (o *optionConfiguratorFunc) Configure(options *pomerium.Options) {
	o.option(options)
}

func NewOptionConfigurator(option pomerium.Option) OptionConfigurator {
	return &optionConfiguratorFunc{
		option: option,
	}
}

// Task represents a background task that can be added to an [Environment] to
// have it run automatically on startup.
//
// For additional details, see [Environment.AddTask] and [Environment.Start].
type Task interface {
	Run(ctx context.Context) error
}

func TaskFunc(fn func(ctx context.Context) error) Task {
	return &taskFunc{fn: fn}
}

// this is a struct wrapper type instead of a typed func so it can be compared
type taskFunc struct {
	fn func(ctx context.Context) error
}

func (f *taskFunc) Run(ctx context.Context) error {
	return f.fn(ctx)
}

// Upstream represents an upstream server. It is both a [Task] and a [Modifier]
// and can be added to an environment using [Environment.AddUpstream]. From an
// Upstream instance, new routes can be created (which automatically adds the
// necessary route/policy entries to the config), and used within a test to
// easily make requests to the routes with implementation-specific clients.
type Upstream interface {
	Modifier
	Task

	Addr() values.Value[string]
	Route() RouteStub
}

// A Route represents a route from a source URL to a destination URL. A route is
// typically created by calling [Upstream.Route].
type Route interface {
	Modifier
	URL() values.Value[string]
	To(toURL values.Value[string]) Route
	Policy(edit func(*config.Policy)) Route
	PPL(ppl string) Route
	// add more methods here as they become needed
}

// RouteStub represents an incomplete [Route]. Providing a URL by calling its
// From() method will return a [Route], from which further configuration can
// be made.
type RouteStub interface {
	From(fromURL values.Value[string]) Route
}
