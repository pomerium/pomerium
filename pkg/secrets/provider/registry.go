package provider

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"

	"github.com/pomerium/pomerium/pkg/secrets/ref"
)

// Registry maps URL schemes to providers. It is the single source of truth for
// which schemes are bindable, shared by config validation and the resolver.
//
// A Registry is safe for concurrent use, and the zero value is an empty
// registry ready to register into.
type Registry struct {
	mu        sync.RWMutex
	providers map[string]Provider
}

// NewRegistry returns an empty Registry.
func NewRegistry() *Registry {
	return &Registry{}
}

// Register adds p under its scheme. Registering a scheme twice is an error and
// leaves the first registration in place.
//
// ref.Parse lowercases every scheme before lookup, so a provider whose Scheme
// is not already lowercase could never be reached; it is rejected here rather
// than registered and silently unreachable.
func (r *Registry) Register(p Provider) error {
	if p == nil {
		return errors.New("secret provider: cannot register a nil provider")
	}
	scheme := p.Scheme()
	if scheme == "" {
		return errors.New("secret provider: cannot register a provider with an empty scheme")
	}
	if scheme != strings.ToLower(scheme) {
		return fmt.Errorf("secret provider: scheme %q must be lowercase", scheme)
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.providers[scheme]; ok {
		return fmt.Errorf("secret provider: scheme %q already registered", scheme)
	}
	if r.providers == nil {
		r.providers = make(map[string]Provider)
	}
	r.providers[scheme] = p
	return nil
}

// Get returns the provider for a scheme.
func (r *Registry) Get(scheme string) (Provider, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.providers[scheme]
	return p, ok
}

// Schemes returns the registered schemes, sorted.
func (r *Registry) Schemes() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return slices.Sorted(maps.Keys(r.providers))
}

// Validate resolves rf's scheme to a provider and delegates strict validation.
func (r *Registry) Validate(rf ref.Ref) error {
	p, ok := r.Get(rf.Scheme())
	if !ok {
		return fmt.Errorf("secret provider: unknown scheme %q (known schemes: %v)", rf.Scheme(), r.Schemes())
	}
	return p.Validate(rf)
}
