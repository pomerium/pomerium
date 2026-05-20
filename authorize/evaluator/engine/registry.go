package engine

import (
	"errors"
	"fmt"
	"sort"
	"sync"

	"github.com/pomerium/pomerium/authorize/evaluator"
)

// A FactoryConfig carries the inputs every PolicyEngine factory may need
// at build time.
//
// EngineConfig is the raw, engine-specific configuration parsed from the
// operator's pomerium config; its shape is owned by the factory.
// EngineConfig may be nil when the operator did not supply a config block.
//
// OPAInner is the OPA-backed evaluator. It is always populated; engines
// that ignore OPA may simply not reference it.
//
// ExternalEnginesEnabled mirrors the external_policy_engine runtime flag.
// Factories for engines other than OPA must refuse to build when this is
// false.
type FactoryConfig struct {
	EngineConfig           any
	OPAInner               *evaluator.Evaluator
	ExternalEnginesEnabled bool
}

// A Factory constructs a PolicyEngine for a given Kind.
type Factory func(FactoryConfig) (PolicyEngine, error)

// A Kind names a registered PolicyEngine implementation.
type Kind string

// Sentinel errors returned by the registry.
var (
	ErrEmptyKind          = errors.New("engine: kind must not be empty")
	ErrNilFactory         = errors.New("engine: factory must not be nil")
	ErrKindAlreadyExists  = errors.New("engine: kind already registered")
	ErrUnknownKind        = errors.New("engine: unknown kind")
	ErrExternalNotAllowed = errors.New("engine: external engines are disabled (set the external_policy_engine runtime flag to enable)")
)

var registry = struct {
	mu        sync.RWMutex
	factories map[Kind]Factory
	external  map[Kind]bool
}{
	factories: map[Kind]Factory{},
	external:  map[Kind]bool{},
}

// Register makes a PolicyEngine factory available under kind.
//
// When external is true the factory builds an engine that talks to an
// out-of-process PDP; Build will refuse to call it unless the runtime
// flag external_policy_engine is set.
//
// Register panics if kind is empty, fn is nil, or kind has already been
// registered. It is intended to be called from package init() functions.
func Register(kind Kind, external bool, fn Factory) {
	if kind == "" {
		panic(ErrEmptyKind)
	}
	if fn == nil {
		panic(ErrNilFactory)
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if _, ok := registry.factories[kind]; ok {
		panic(fmt.Errorf("%w: %q", ErrKindAlreadyExists, kind))
	}
	registry.factories[kind] = fn
	registry.external[kind] = external
}

// Build returns the PolicyEngine for kind, using cfg to construct it.
// An empty kind selects KindOPA.
func Build(kind Kind, cfg FactoryConfig) (PolicyEngine, error) {
	if kind == "" {
		kind = KindOPA
	}
	registry.mu.RLock()
	fn, ok := registry.factories[kind]
	external := registry.external[kind]
	registry.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownKind, kind)
	}
	if external && !cfg.ExternalEnginesEnabled {
		return nil, fmt.Errorf("%w: kind=%q", ErrExternalNotAllowed, kind)
	}
	return fn(cfg)
}

// RegisteredKinds returns the sorted list of registered engine kinds.
func RegisteredKinds() []Kind {
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	kinds := make([]Kind, 0, len(registry.factories))
	for k := range registry.factories {
		kinds = append(kinds, k)
	}
	sort.Slice(kinds, func(i, j int) bool { return kinds[i] < kinds[j] })
	return kinds
}
