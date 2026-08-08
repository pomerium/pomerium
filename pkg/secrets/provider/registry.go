package provider

import (
	"fmt"
	"slices"

	"github.com/pomerium/pomerium/pkg/secrets/ref"
)

// Registry maps URL schemes to providers. It is the single source of truth for
// which schemes are bindable, shared by config validation and the resolver.
type Registry struct {
	providers map[string]Provider
}

// NewRegistry returns an empty Registry.
func NewRegistry() *Registry {
	return &Registry{providers: make(map[string]Provider)}
}

// Register adds p under its scheme. Registering a scheme twice is an error.
func (r *Registry) Register(p Provider) error {
	scheme := p.Scheme()
	if _, ok := r.providers[scheme]; ok {
		return fmt.Errorf("secret provider: scheme %q already registered", scheme)
	}
	r.providers[scheme] = p
	return nil
}

// Get returns the provider for a scheme.
func (r *Registry) Get(scheme string) (Provider, bool) {
	p, ok := r.providers[scheme]
	return p, ok
}

// Schemes returns the registered schemes, sorted.
func (r *Registry) Schemes() []string {
	schemes := make([]string, 0, len(r.providers))
	for scheme := range r.providers {
		schemes = append(schemes, scheme)
	}
	slices.Sort(schemes)
	return schemes
}

// Validate resolves r's scheme to a provider and delegates strict validation.
func (r *Registry) Validate(rf ref.Ref) error {
	p, ok := r.providers[rf.Scheme()]
	if !ok {
		return fmt.Errorf("secret provider: unknown scheme %q (known schemes: %v)", rf.Scheme(), r.Schemes())
	}
	return p.Validate(rf)
}
