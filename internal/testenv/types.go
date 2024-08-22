package testenv

import (
	"context"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/testenv/values"
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

type Modifiers []Modifier

func (m Modifiers) Modify(cfg *config.Config) {
	for _, mod := range m {
		mod.Modify(cfg)
	}
}

type ModifierFunc func(cfg *config.Config)

func (f ModifierFunc) Modify(cfg *config.Config) {
	f(cfg)
}

// Task represents a background task that can be added to an [Environment] to
// have it run automatically on startup.
//
// For additional details, see [Environment.AddTask] and [Environment.Start].
type Task interface {
	Run(ctx context.Context) error
}

type TaskFunc func(ctx context.Context) error

func (f TaskFunc) Run(ctx context.Context) error {
	return f(ctx)
}

// Upstream represents an upstream server. It is both a [Task] and a [Modifier]
// and can be added to an environment using [Environment.AddUpstream]. From an
// Upstream instance, new routes can be created (which automatically adds the
// necessary route/policy entries to the config), and used within a test to
// easily make requests to the routes with implementation-specific clients.
type Upstream interface {
	Modifier
	Task
	Port() values.Value[int]
	Route() RouteStub
}

// A Route represents a route from a source URL to a destination URL. A route is
// typically created by calling [Upstream.Route].
type Route interface {
	Modifier
	URL() values.Value[string]
	To(toUrl values.Value[string]) Route
	Policy(edit func(*config.Policy)) Route
	// add more methods here as they become needed
}

// RouteStub represents an incomplete [Route]. Providing a URL by calling its
// From() method will return a [Route], from which further configuration can
// be made.
type RouteStub interface {
	From(fromUrl values.Value[string]) Route
}
